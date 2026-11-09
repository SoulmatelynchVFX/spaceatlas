"""Inspect one explicitly selected installation, not an application's full footprint."""
from dataclasses import asdict
from pathlib import Path, PureWindowsPath
import re
import stat

from .scanner import directory_stats, should_skip, validate_limits, validate_top_files, validate_exclude_dirs
from .windows_inventory import InventoryResult
from .scan_report import SCAN_NOTE, scan_report
from .scanner import validate_max_depth, validate_min_size, validate_extension_filters


def valid_install_location(value: str) -> bool:
    """Accept only a fully qualified local drive path below the drive root."""
    path = PureWindowsPath(value)
    return bool(
        re.fullmatch(r"[a-zA-Z]:", path.drive)
        and path.root and len(path.parts) > 1
        and ".." not in path.parts
        and not any(part.endswith((".", " ")) for part in path.parts[1:])
        and not any(ord(char) < 32 for char in value)
        and not any(char in value[2:] for char in '\x00%"*?:<>|')
    )


def inspect_app(inventory: InventoryResult, app_id: str, *, max_files=None, max_seconds=None,
                top_files=None, exclude_dirs=None, by_extension=False, by_directory=False,
                on_file=None, max_depth=None, min_size=None, include_ext=None, exclude_ext=None) -> dict:
    validate_limits(max_files, max_seconds)
    validate_max_depth(max_depth)
    validate_min_size(min_size)
    validate_top_files(top_files)
    included_exts, excluded_exts = validate_extension_filters(include_ext, exclude_ext)
    excluded_names = validate_exclude_dirs(exclude_dirs)
    report = {
        "requested_app_id": app_id,
        "scope": "install_location_only",
        "application": None,
        "scan": None,
        "partial": inventory.partial,
        "inventory": {"partial": inventory.partial, "error_count": inventory.error_count,
                      "errors": inventory.errors, "missing_locations": inventory.missing_locations},
        "note": "仅统计注册表声明的安装目录，可能包含共享文件；不等于应用全部数据。" + SCAN_NOTE,
    }

    def unavailable(message):
        report.update(partial=True, error=message)
        return report

    matches = [app for app in inventory.applications if app.app_id == app_id]
    if len(matches) != 1:
        return unavailable("未找到唯一匹配的应用 ID；请重新运行 --list-apps 获取当前 ID。")
    app = matches[0]
    report["application"] = asdict(app)
    if not app.install_location:
        return unavailable("应用没有声明安装目录；不从卸载命令猜测路径。")
    if not valid_install_location(app.install_location):
        return unavailable("安装目录必须是本地盘符下的绝对目录；不扫描盘符根、网络或设备路径，也不展开环境变量。")
    path = Path(app.install_location)
    try:
        info = path.lstat()
    except OSError as error:
        return unavailable(f"无法读取安装目录：{error}")
    if should_skip(info) or not stat.S_ISDIR(info.st_mode):
        return unavailable("安装位置不是普通目录，或带有链接、离线属性；未开始扫描。")
    stats = directory_stats(path, max_files=max_files, max_seconds=max_seconds,
                            top_files=top_files, exclude_dirs=excluded_names, by_extension=by_extension,
                            by_directory=by_directory,
                            **({"max_depth": max_depth} if max_depth is not None else {}),
                            **({"min_size": min_size} if min_size is not None else {}),
                            **({"include_ext": included_exts} if included_exts else {}),
                            **({"exclude_ext": excluded_exts} if excluded_exts else {}),
                            **({"on_file": on_file} if on_file is not None else {}))
    report["scan"] = scan_report(stats)
    report["partial"] = inventory.partial or stats.partial
    return report
