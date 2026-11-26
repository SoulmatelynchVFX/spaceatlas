from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.domain import InstalledApp
from storage_inspector.progress import ProgressReporter, ProgressOutputError
from storage_inspector.scanner import DirectoryStats, directory_stats
from storage_inspector.windows_inventory import InventoryResult


def events(text):
    return [json.loads(line[len("progress "):]) for line in text.splitlines()
            if line.startswith("progress ")]


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        (self.root / "nested").mkdir()
        (self.root / "a").write_bytes(b"abc")
        (self.root / "nested" / "b").write_bytes(b"de")

    def cli(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_default_does_not_construct_reporter_or_write_progress(self):
        with patch("storage_inspector.__main__.ProgressReporter") as reporter:
            code, out, err = self.cli("--path", str(self.root))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        reporter.assert_not_called()
        self.assertEqual(json.loads(out)["file_count"], 2)

    def test_all_formats_keep_stdout_identical_and_separate_diagnostics(self):
        for fmt in ("json", "csv", "ndjson"):
            args = ("--path", str(self.root), "--format", fmt)
            before = self.cli(*args)
            code, out, err = self.cli(*args, "--progress")
            self.assertEqual((code, out), before[:2])
            updates = events(err)
            self.assertEqual(updates[0]["state"], "scanning")
            self.assertEqual(updates[-1]["state"], "finished")
            self.assertEqual((updates[-1]["file_count"], updates[-1]["logical_bytes"]), (2, 5))
            self.assertFalse(updates[-1]["partial"])
            self.assertFalse(any(key in updates[-1] for key in ("path", "percentage", "total")))
            if fmt == "csv":
                self.assertEqual(json.loads(err.splitlines()[-1])["csv"]["rows_written"], 2)

    def test_updates_are_throttled_but_final_update_is_always_emitted(self):
        stream = StringIO()
        reporter = ProgressReporter(stream)
        stats = DirectoryStats("fixture")
        with patch("storage_inspector.progress.time.monotonic", side_effect=[0, 0.2, 1, 1.1]):
            reporter.update(stats)
            stats.file_count = 1
            reporter.update(stats)
            stats.file_count = 2
            reporter.update(stats)
            reporter.update(stats, finished=True)
        self.assertEqual([event["file_count"] for event in events(stream.getvalue())], [0, 2, 2])
        self.assertEqual(events(stream.getvalue())[-1]["state"], "finished")

    def test_progress_does_not_add_directory_traversals_or_file_reads(self):
        original = os.scandir
        with patch("os.scandir", wraps=original) as scan:
            directory_stats(self.root)
            baseline = scan.call_count
        with patch("os.scandir", wraps=original) as scan, \
                patch.object(Path, "open", side_effect=AssertionError("no content reads")):
            stats = directory_stats(self.root, on_progress=ProgressReporter(StringIO()).update)
            self.assertEqual(scan.call_count, baseline)
        self.assertEqual(stats.logical_bytes, 5)

    def test_filtering_and_max_files_final_update_preserve_partial_status(self):
        code, out, err = self.cli("--path", str(self.root), "--progress", "--max-files", "1")
        report = json.loads(out)
        self.assertEqual(code, 2)
        final = events(err)[-1]
        self.assertEqual(final["stop_reason"], "max_files")
        self.assertTrue(final["partial"])
        self.assertEqual(final["file_count"], report["file_count"])
        code, out, err = self.cli("--path", str(self.root), "--progress", "--min-size", "3")
        self.assertEqual(code, 2)
        self.assertEqual(events(err)[-1]["file_count"], 1)

    def test_empty_and_missing_targets_are_not_invented_as_complete_data(self):
        empty = self.root / "empty"
        empty.mkdir()
        self.assertEqual(events(self.cli("--path", str(empty), "--progress")[2])[-1]["file_count"], 0)
        code, out, err = self.cli("--path", str(self.root / "missing"), "--progress")
        self.assertEqual(code, 2)
        self.assertEqual(events(err)[-1]["error_count"], 1)
        self.assertTrue(json.loads(out)["partial"])

    def test_interrupt_keeps_final_observed_counts_and_exit_status(self):
        stream = StringIO()
        def interrupt(*args):
            raise KeyboardInterrupt
        stats = directory_stats(self.root, on_progress=ProgressReporter(stream).update, on_file=interrupt)
        final = events(stream.getvalue())[-1]
        self.assertEqual(stats.stop_reason, "interrupted")
        self.assertEqual(final["stop_reason"], "interrupted")
        self.assertTrue(final["partial"])
        self.assertEqual(final["file_count"], 1)
        def interrupting_scan(path, **kwargs):
            writer = kwargs.get("on_file")
            def emit_then_interrupt(*args):
                if writer is not None:
                    writer(*args)
                interrupt()
            kwargs["on_file"] = emit_then_interrupt
            return directory_stats(path, **kwargs)
        for fmt in ("json", "csv", "ndjson"):
            with patch("storage_inspector.__main__.directory_stats", side_effect=interrupting_scan):
                code, out, err = self.cli("--path", str(self.root), "--progress", "--format", fmt)
            self.assertEqual(code, 130)
            self.assertEqual(events(err)[-1]["stop_reason"], "interrupted")
            if fmt == "json":
                self.assertEqual(json.loads(out)["stop_reason"], "interrupted")
            elif fmt == "csv":
                self.assertEqual(json.loads(err.splitlines()[-1])["stop_reason"], "interrupted")
            else:
                self.assertEqual(json.loads(out.splitlines()[-1])["report"]["stop_reason"], "interrupted")

    def test_time_limit_still_finishes_with_partial_counts(self):
        clock = [0]
        stream = StringIO()
        def advance(*args):
            clock[0] = 2
        with patch("storage_inspector.scanner.time.monotonic", side_effect=lambda: clock[0]):
            stats = directory_stats(self.root, max_seconds=1, on_file=advance,
                                    on_progress=ProgressReporter(stream).update)
        self.assertEqual(stats.stop_reason, "max_seconds")
        self.assertEqual(events(stream.getvalue())[-1]["stop_reason"], "max_seconds")
        self.assertEqual(events(stream.getvalue())[-1]["file_count"], 1)

    def test_saved_report_contains_no_progress_lines(self):
        with TemporaryDirectory() as destination:
            output = Path(destination) / "report.json"
            code, out, err = self.cli("--path", str(self.root), "--progress", "--output", str(output))
            self.assertEqual(code, 0)
            self.assertEqual(out, "")
            self.assertEqual(json.loads(output.read_text())["file_count"], 2)
            self.assertEqual(events(err)[-1]["file_count"], 2)

    def test_diagnostics_failure_is_not_a_source_error_or_partial_saved_report(self):
        class BrokenStream(StringIO):
            def write(self, text):
                raise OSError("diagnostic failure")
        with TemporaryDirectory() as destination:
            output = Path(destination) / "report.json"
            output.write_text("keep")
            with redirect_stdout(StringIO()), redirect_stderr(BrokenStream()):
                code = main(["--path", str(self.root), "--progress", "--output", str(output), "--force"])
            self.assertEqual(code, 1)
            self.assertEqual(output.read_text(), "keep")
        with self.assertRaises(ProgressOutputError):
            ProgressReporter(BrokenStream()).update(DirectoryStats("fixture"))

    def test_inventory_flag_rejected_before_registry_io(self):
        with patch("storage_inspector.__main__.discover_inventory") as discover:
            with self.assertRaises(SystemExit):
                self.cli("--list-apps", "--progress")
        discover.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows installation paths")
    def test_application_scanning_forwards_progress_without_expanding_scope(self):
        inv = InventoryResult([InstalledApp("fixture", "Fixture", install_location=str(self.root / "nested"))])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inv):
            code, out, err = self.cli("--app", "fixture", "--progress")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["scan"]["logical_bytes"], 2)
        self.assertEqual(events(err)[-1]["logical_bytes"], 2)

    @unittest.skipUnless(os.name == "nt", "Windows inventory entry")
    def test_refused_app_scan_does_not_claim_progress_started(self):
        with patch("storage_inspector.__main__.discover_inventory", return_value=InventoryResult()):
            code, out, err = self.cli("--app", "unknown", "--progress")
        self.assertEqual(code, 2)
        self.assertIsNone(json.loads(out)["scan"])
        self.assertEqual(events(err), [])
