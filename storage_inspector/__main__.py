"""Explicit metadata scans and opt-in report export; no automatic disk scan."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys

from .app_scan import inspect_app
from .csv_output import CsvFileWriter, CsvOutputError, CsvOutputInterrupted
from .ndjson_output import NdjsonFileWriter, NdjsonOutputError, NdjsonOutputInterrupted
from .scanner import directory_stats, validate_limits, validate_top_files, validate_exclude_dirs
from .windows_inventory import discover_inventory
from .report_output import ReportOutput, ReportOutputError


SCHEMA_VERSION = 1


def _main(argv=None):
    parser = argparse.ArgumentParser(description="璃盘：只读应用清单与指定路径统计")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list-apps", action="store_true", help="读取 Windows 卸载注册表，不扫描目录")
    action.add_argument("--path", type=Path, help="只统计指定文件或目录的逻辑字节数")
    action.add_argument("--app", metavar="APP_ID", help="按清单 ID 只统计该应用声明的安装目录")
    parser.add_argument("--max-files", type=int, help="扫描至多计入指定数量的文件，必须为正整数")
    parser.add_argument("--max-seconds", type=float, help="扫描时长软限制（秒），必须为有限正数")
    parser.add_argument("--top-files", type=int, help="列出已计入文件中逻辑长度最大的前 N 项，必须为正整数")
    parser.add_argument("--exclude-dir", action="append", metavar="NAME",
                        help="跳过同名子目录（不区分大小写，可重复指定，不接受路径或通配符）")
    parser.add_argument("--by-extension", action="store_true", help="按文件名最后一个扩展名汇总占用，不读取正文")
    parser.add_argument("--by-directory", action="store_true", help="按一级子目录汇总已计入文件，根目录直属文件单列")
    parser.add_argument("--format", choices=("json", "csv", "ndjson"), default="json",
                        help="输出格式；csv 状态写 stderr；ndjson 逐行输出文件事件及结束汇总")
    parser.add_argument("--output", type=Path, help="保存到扫描范围外的指定文件（UTF-8），默认拒绝覆盖")
    parser.add_argument("--force", action="store_true", help="配合 --output 替换已有普通单链接文件")
    args = parser.parse_args(argv)
    if args.force and args.output is None:
        parser.error("--force 必须与 --output 同时使用")
    try:
        validate_limits(args.max_files, args.max_seconds)
        validate_top_files(args.top_files)
        excluded_names = validate_exclude_dirs(args.exclude_dir)
    except ValueError as error:
        parser.error(str(error))
    if args.format == "ndjson" and args.list_apps:
        parser.error("--format ndjson 仅用于 --path 或 --app，不能用于 --list-apps")
    if args.format == "csv":
        if args.list_apps:
            parser.error("--format csv 仅用于 --path 或 --app，不能用于 --list-apps")
        for option, enabled in (("--by-extension", args.by_extension),
                                ("--by-directory", args.by_directory),
                                ("--top-files", args.top_files is not None)):
            if enabled:
                parser.error(f"--format csv 不能与 {option} 同时使用")
    if args.list_apps and (args.max_files is not None or args.max_seconds is not None):
        parser.error("扫描限制仅用于 --path 或 --app，不能用于 --list-apps")
    if args.list_apps and args.top_files is not None:
        parser.error("--top-files 仅用于 --path 或 --app，不能用于 --list-apps")
    if args.list_apps and args.exclude_dir is not None:
        parser.error("--exclude-dir 仅用于 --path 或 --app，不能用于 --list-apps")
    if args.list_apps and args.by_extension:
        parser.error("--by-extension 仅用于 --path 或 --app，不能用于 --list-apps")
    if args.list_apps and args.by_directory:
        parser.error("--by-directory 仅用于 --path 或 --app，不能用于 --list-apps")
    inventory = None
    if args.list_apps or args.app is not None:
        if os.name != "nt":
            parser.error("--list-apps 和 --app 仅支持 Windows")
        inventory = discover_inventory()
    if args.output is not None:
        roots = [args.path] if args.path is not None else []
        if args.app is not None:
            roots = [app.install_location for app in inventory.applications
                     if app.app_id == args.app and app.install_location]
        with ReportOutput(args.output, roots, force=args.force) as destination:
            status = _render(args, inventory, excluded_names, destination.stream)
            destination.commit()
        return status
    return _render(args, inventory, excluded_names, sys.stdout)


def _render(args, inventory, excluded_names, output):
    csv_output = CsvFileWriter(output) if args.format == "csv" else None
    ndjson_output = NdjsonFileWriter(output, SCHEMA_VERSION) if args.format == "ndjson" else None
    file_output = csv_output if csv_output is not None else ndjson_output
    scan_options = {"on_file": file_output.write_file} if file_output is not None else {}
    if args.app is not None:
        report_type = "application_scan"
        report = inspect_app(inventory, args.app, max_files=args.max_files,
                             max_seconds=args.max_seconds, top_files=args.top_files,
                             exclude_dirs=excluded_names, by_extension=args.by_extension,
                             by_directory=args.by_directory, **scan_options)
        scan = report.get("scan") or {}
        status = 130 if scan.get("stop_reason") == "interrupted" else 2 if report["partial"] else 0
    elif args.list_apps:
        report_type = "application_inventory"
        report = {
            **asdict(inventory),
            "source": "Windows uninstall registry",
            "partial": inventory.partial,
            "note": "注册表清单可能不完整；安装位置不代表应用全部数据，没有执行卸载命令。",
        }
        status = 2 if inventory.partial else 0
    else:
        report_type = "path_scan"
        stats = directory_stats(args.path, max_files=args.max_files,
                                max_seconds=args.max_seconds, top_files=args.top_files,
                                exclude_dirs=excluded_names, by_extension=args.by_extension,
                                by_directory=args.by_directory, **scan_options)
        report = {**asdict(stats), "partial": stats.partial,
                  "note": "逻辑长度不是磁盘实际分配量或可清理容量；扫描期间变化可能造成误差。"}
        status = 130 if stats.stop_reason == "interrupted" else 2 if stats.partial else 0
    # The top-level version governs the complete document, including nested objects.
    report = {"schema_version": SCHEMA_VERSION, "report_type": report_type, **report}
    if csv_output is not None:
        csv_output.finish(report, sys.stderr)
        if csv_output.missing_modified and status == 0:
            status = 2
    elif ndjson_output is not None:
        status = ndjson_output.finish(report, status)
    else:
        # ASCII escaping also makes redirected output usable with legacy Windows encodings.
        print(json.dumps(report, ensure_ascii=True, indent=2), file=output)
    return status


def main(argv=None):
    try:
        return _main(argv)
    except ReportOutputError as error:
        print(f"报告保存失败：{error}", file=sys.stderr)
        return 1
    except CsvOutputError as error:
        print(f"CSV 输出失败，结果可能不完整：{error}", file=sys.stderr)
        return 1
    except CsvOutputInterrupted:
        print("CSV 输出已中断，最后一行可能不完整，未生成扫描状态或保存新报告。", file=sys.stderr)
        return 130
    except NdjsonOutputError as error:
        print(f"NDJSON 输出失败，结果可能不完整：{error}", file=sys.stderr)
        return 1
    except NdjsonOutputInterrupted:
        print("NDJSON 输出已中断，最后一行可能不完整，未追加结束汇总。", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        # Inventory discovery and output may be interrupted before a report is ready.
        print("操作已中断，未输出完整报告。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
