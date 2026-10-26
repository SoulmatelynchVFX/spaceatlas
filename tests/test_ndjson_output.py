from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.ndjson_output import NdjsonFileWriter, NdjsonOutputError
from storage_inspector.windows_inventory import InventoryResult


class NdjsonOutputTests(unittest.TestCase):
    def run_stream(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main([*args, "--format", "ndjson"])
        self.assertEqual(errors.getvalue(), "")
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(events[-1]["event"], "summary")
        self.assertEqual(events[-1]["exit_code"], status)
        self.assertTrue(all(event["schema_version"] == 1 for event in events))
        self.assertEqual(sum(e["event"] == "summary" for e in events), 1)
        return status, events[:-1], events[-1]["report"]

    def test_empty_directory_emits_only_complete_summary(self):
        with tempfile.TemporaryDirectory() as root:
            status, files, report = self.run_stream(["--path", root])
        self.assertEqual((status, files), (0, []))
        self.assertFalse(report["partial"])
        self.assertEqual(report["ndjson"], {"files_written": 0, "missing_modified": 0})

    def test_metadata_is_read_once_without_file_contents(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "中文,文件.txt"
            file.write_bytes(b"abc")
            os.utime(file, (1704067200, 1704067200))
            original = Path.lstat
            reads = []
            def observed(path):
                reads.append(path)
                return original(path)
            with patch.object(Path, "open", side_effect=AssertionError("no content reads")), \
                    patch.object(Path, "lstat", new=observed):
                status, files, report = self.run_stream(["--path", str(file)])
        self.assertEqual(status, 0)
        self.assertEqual(reads, [file])
        self.assertEqual(files, [{"schema_version": 1, "event": "file", "path": str(file),
                                 "size": 3, "modified": "2024-01-01T00:00:00.000000Z"}])
        self.assertEqual(report["file_count"], report["ndjson"]["files_written"])
        self.assertEqual(report["logical_bytes"], 3)

    def test_unicode_quotes_and_newlines_stay_in_one_record(self):
        output = io.StringIO()
        writer = NdjsonFileWriter(output, 1)
        name = 'C:/synthetic/中文,"name"\r\n.txt'
        writer.write_file(name, SimpleNamespace(st_size=0, st_mtime=0))
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertTrue(output.getvalue().isascii())
        self.assertEqual(json.loads(output.getvalue())["path"], name)

    def test_missing_modified_is_null_and_partial(self):
        for timestamp in (None, float("inf"), float("nan"), 1e100):
            info = SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1, st_ino=1,
                                   st_size=0, st_mtime=timestamp)
            with self.subTest(timestamp=timestamp), patch.object(Path, "lstat", return_value=info):
                status, files, report = self.run_stream(["--path", "synthetic"])
            self.assertEqual(status, 2)
            self.assertIsNone(files[0]["modified"])
            self.assertTrue(report["partial"])
            self.assertEqual(report["ndjson"]["missing_modified"], 1)

    def test_invalid_options_emit_nothing_and_do_not_scan(self):
        for args in (["--list-apps"], ["--path", ".", "--max-files", "0"]):
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(args=args), redirect_stdout(output), redirect_stderr(errors), \
                    patch("storage_inspector.__main__.discover_inventory") as inventory, \
                    patch("storage_inspector.__main__.directory_stats") as scan:
                with self.assertRaises(SystemExit) as raised:
                    main([*args, "--format", "ndjson"])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(output.getvalue(), "")
            scan.assert_not_called()
            inventory.assert_not_called()

    def test_file_limit_emits_partial_summary(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("a", "b"):
                (Path(root) / name).write_bytes(b"x")
            status, files, report = self.run_stream(["--path", root, "--max-files", "1"])
        self.assertEqual((status, len(files)), (2, 1))
        self.assertEqual(report["stop_reason"], "max_files")
        self.assertTrue(report["partial"])

    def test_time_limit_before_first_file_still_emits_partial_summary(self):
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            status, files, report = self.run_stream(["--path", "synthetic", "--max-seconds", "1"])
        self.assertEqual((status, files), (2, []))
        self.assertEqual(report["stop_reason"], "max_seconds")

    def test_excluded_directory_is_not_emitted(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "skip").mkdir()
            (Path(root) / "skip" / "hidden").write_bytes(b"abc")
            (Path(root) / "visible").write_bytes(b"x")
            status, files, report = self.run_stream(["--path", root, "--exclude-dir", "skip"])
        self.assertEqual((status, len(files)), (2, 1))
        self.assertEqual(report["logical_bytes"], 1)
        self.assertEqual(report["excluded_directories"], 1)

    def test_hardlinks_emit_only_first_path(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "first").write_bytes(b"abc")
            os.link(Path(root) / "first", Path(root) / "second")
            status, files, report = self.run_stream(["--path", root])
        self.assertEqual((status, len(files)), (0, 1))
        self.assertEqual(report["duplicates"], 1)
        self.assertEqual(report["logical_bytes"], 3)

    def test_skips_and_access_failures_are_not_empty_success(self):
        for info, reason in ((SimpleNamespace(st_mode=stat.S_IFLNK), "symbolic_link"),
                             (SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400), "reparse_point"),
                             (SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x1000), "offline")):
            with self.subTest(reason=reason), patch.object(Path, "lstat", return_value=info):
                status, files, report = self.run_stream(["--path", "synthetic"])
            self.assertEqual((status, files), (2, []))
            self.assertEqual(report["skip_reason_counts"], {reason: 1})
        with patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            status, files, report = self.run_stream(["--path", "synthetic"])
        self.assertEqual((status, files), (2, []))
        self.assertEqual(report["error_count"], 1)

    def test_file_is_flushed_before_next_entry_and_interrupt_closes_iterator(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "sample"
            file.write_bytes(b"x")
            output, errors = io.StringIO(), io.StringIO()
            flushed = []
            class Entries:
                count = 0
                closed = False
                def __next__(self):
                    self.count += 1
                    if self.count == 1:
                        return file
                    assert json.loads(output.getvalue())["event"] == "file"
                    assert len(flushed) == 1
                    raise KeyboardInterrupt
                def close(self):
                    self.closed = True
            entries = Entries()
            with patch("storage_inspector.scanner.os.scandir", return_value=entries), \
                    patch.object(output, "flush", side_effect=lambda: flushed.append(True)), \
                    redirect_stdout(output), redirect_stderr(errors):
                status = main(["--path", root, "--format", "ndjson"])
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(status, 130)
        self.assertEqual(events[-1]["exit_code"], 130)
        self.assertEqual(events[-1]["report"]["stop_reason"], "interrupted")
        self.assertTrue(entries.closed)
        self.assertEqual(len(events), 2)
        self.assertEqual(errors.getvalue(), "")

    def test_aggregates_appear_only_in_final_report(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "a.txt").write_bytes(b"abc")
            status, files, report = self.run_stream(["--path", root, "--by-extension",
                                                   "--by-directory", "--top-files", "1"])
        self.assertEqual(status, 0)
        self.assertEqual(len(files), 1)
        self.assertEqual(report["extension_summary"][0]["logical_bytes"], 3)
        self.assertEqual(report["directory_summary"][0]["logical_bytes"], 3)
        self.assertEqual(report["largest_files"][0]["logical_bytes"], 3)

    def test_app_scope_inventory_errors_and_rejected_id(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "sample").write_bytes(b"x")
            inventory = InventoryResult(applications=[InstalledApp("sample", "Example", install_location=root)])
            inventory.record_error("HKLM", "open_root", PermissionError("denied"))
            with patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                    patch("storage_inspector.__main__.discover_inventory", return_value=inventory), \
                    patch("storage_inspector.app_scan.valid_install_location", return_value=True):
                status, files, report = self.run_stream(["--app", "sample"])
                rejected, no_files, missing = self.run_stream(["--app", "unknown"])
        self.assertEqual((status, len(files)), (2, 1))
        self.assertEqual(report["scope"], "install_location_only")
        self.assertEqual(report["inventory"]["error_count"], 1)
        self.assertFalse(report["scan"]["partial"])
        self.assertEqual((rejected, no_files), (2, []))
        self.assertIsNone(missing["scan"])

    def test_early_inventory_interrupt_has_no_summary(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch("storage_inspector.__main__.os", SimpleNamespace(name="nt")), \
                patch("storage_inspector.__main__.discover_inventory", side_effect=KeyboardInterrupt), \
                redirect_stdout(output), redirect_stderr(errors):
            status = main(["--app", "sample", "--format", "ndjson"])
        self.assertEqual(status, 130)
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(errors.getvalue())

    def test_destination_failure_or_interrupt_does_not_append_summary(self):
        for exception, expected in ((OSError("full"), 1), (UnicodeError("encoding"), 1),
                                    (KeyboardInterrupt(), 130)):
            class BrokenOutput(io.StringIO):
                def write(self, value):
                    super().write(value[:10])
                    raise exception
            info = SimpleNamespace(st_mode=stat.S_IFREG, st_size=1, st_ino=1, st_dev=1, st_mtime=0)
            output, errors = BrokenOutput(), io.StringIO()
            with self.subTest(exception=type(exception)), patch.object(Path, "lstat", return_value=info), \
                    redirect_stdout(output), redirect_stderr(errors):
                status = main(["--path", "synthetic", "--format", "ndjson"])
            self.assertEqual(status, expected)
            self.assertEqual(output.getvalue(), '{"schema_v')
            self.assertNotIn("summary", output.getvalue())
            self.assertTrue(errors.getvalue())

    def test_flush_and_short_write_failures_are_output_errors(self):
        info = SimpleNamespace(st_size=1, st_mtime=0)
        for operation in ("flush", "write"):
            output = io.StringIO()
            writer = NdjsonFileWriter(output, 1)
            replacement = {"side_effect": OSError("full")} if operation == "flush" else {"return_value": 1}
            with self.subTest(operation=operation), patch.object(output, operation, **replacement):
                with self.assertRaises(NdjsonOutputError):
                    writer.write_file("synthetic", info)
            self.assertEqual(writer.files_written, 0)

    def test_summary_write_failure_returns_nonzero(self):
        class BrokenSummary(io.StringIO):
            def write(self, value):
                if '"event":"summary"' in value:
                    raise OSError("summary destination full")
                return super().write(value)
        output, errors = BrokenSummary(), io.StringIO()
        with tempfile.TemporaryDirectory() as root, redirect_stdout(output), redirect_stderr(errors):
            status = main(["--path", root, "--format", "ndjson"])
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "")

    def test_process_output_is_ascii_compatible_ndjson_with_final_summary(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "中文.txt").write_bytes(b"x")
            result = subprocess.run([sys.executable, "-m", "storage_inspector", "--path", root,
                                     "--format", "ndjson"], cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        events = [json.loads(line) for line in result.stdout.decode("ascii").splitlines()]
        self.assertTrue(events[0]["path"].endswith("中文.txt"))
        self.assertEqual(events[-1]["event"], "summary")
        self.assertTrue(result.stdout.endswith(b"\n"))

    def test_schema_document_matches_event_fields(self):
        document = (Path(__file__).resolve().parents[1] / "docs/schema.md").read_text(encoding="utf-8")
        output = io.StringIO()
        writer = NdjsonFileWriter(output, 1)
        writer.write_file("synthetic", SimpleNamespace(st_size=1, st_mtime=0))
        writer.finish({"schema_version": 1, "partial": False}, 0)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        for heading, event in zip(("NDJSON 文件事件", "NDJSON 结束事件"), events):
            section = document.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
            fields = set(re.findall(r"^\| `([^`]+)` \|", section, re.MULTILINE))
            self.assertEqual(set(event), fields)


if __name__ == "__main__":
    unittest.main()
