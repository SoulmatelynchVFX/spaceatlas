"""Exercise CLI output interruption at external stream/filesystem boundaries."""
from contextlib import redirect_stderr, redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main


class InterruptingStream:
    """Write part of one selected chunk, then simulate a single Ctrl+C."""
    def __init__(self, stream, interrupt_at=2):
        self.stream = stream
        self.interrupt_at = interrupt_at
        self.writes = 0

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def write(self, text):
        self.writes += 1
        if self.writes == self.interrupt_at:
            self.stream.write(text[:max(1, len(text) // 2)])
            raise KeyboardInterrupt
        return self.stream.write(text)


class OutputInterruptContractTests(unittest.TestCase):
    def test_traversal_interrupt_still_saves_well_formed_partial_in_all_formats(self):
        for fmt in ("json", "csv", "ndjson"):
            with self.subTest(format=fmt), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source"
                source.mkdir()
                (source / "sample.txt").write_bytes(b"abc")
                target = root / ("report." + fmt)
                original_scandir = os.scandir
                def interrupted_directory(path):
                    if Path(path) != source:
                        return original_scandir(path)
                    def entries():
                        with original_scandir(path) as iterator:
                            yield next(iterator)
                            raise KeyboardInterrupt
                    return entries()
                output, errors = io.StringIO(), io.StringIO()
                with patch("os.scandir", side_effect=interrupted_directory), \
                        redirect_stdout(output), redirect_stderr(errors):
                    status = main(["--path", str(source), "--format", fmt, "--output", str(target)])
                self.assertEqual(status, 130)
                self.assertEqual(output.getvalue(), "")
                text = target.read_text(encoding="utf-8")
                if fmt == "json":
                    report = json.loads(text)
                elif fmt == "csv":
                    rows = list(csv.reader(io.StringIO(text)))
                    self.assertEqual(len(rows), 2)
                    self.assertEqual(rows[1][1], "3")
                    report = json.loads(errors.getvalue())
                    self.assertEqual(report["csv"]["rows_written"], 1)
                else:
                    events = [json.loads(line) for line in text.splitlines()]
                    self.assertEqual(len(events), 2)
                    self.assertEqual(events[-1]["event"], "summary")
                    self.assertEqual(events[-1]["exit_code"], 130)
                    report = events[-1]["report"]
                self.assertEqual((report["file_count"], report["logical_bytes"]), (1, 3))
                self.assertEqual(report["stop_reason"], "interrupted")
                self.assertTrue(report["partial"])
                self.assertEqual(list(root.glob(".spaceatlas-*.tmp")), [])

    def test_csv_stdout_interrupt_reports_torn_row_without_scan_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "sample.txt").write_bytes(b"abc")
            captured, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(InterruptingStream(captured)), redirect_stderr(errors):
                status = main(["--path", directory, "--format", "csv"])
            self.assertEqual(status, 130)
            self.assertTrue(captured.getvalue().startswith("path,size,modified\r\n"))
            self.assertFalse(captured.getvalue().endswith("\n"))
            self.assertNotIn('"schema_version"', errors.getvalue())
            self.assertIn("最后一行可能不完整", errors.getvalue())

    def test_output_interruption_discards_new_or_replacement_files_in_all_formats(self):
        for fmt, chunk in (("json", 1), ("csv", 1), ("csv", 2), ("ndjson", 1)):
            for exists in (False, True):
                with self.subTest(format=fmt, chunk=chunk, exists=exists), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "source"
                    source.mkdir()
                    (source / "sample.txt").write_bytes(b"abc")
                    target = root / ("report." + fmt)
                    if exists:
                        target.write_bytes(b"original report\n")
                    original_fdopen = os.fdopen
                    def interrupted_file(*args, **kwargs):
                        return InterruptingStream(original_fdopen(*args, **kwargs), chunk)
                    output, errors = io.StringIO(), io.StringIO()
                    with patch("os.fdopen", side_effect=interrupted_file), \
                            redirect_stdout(output), redirect_stderr(errors):
                        status = main(["--path", str(source), "--format", fmt,
                                       "--output", str(target), *(["--force"] if exists else [])])
                    self.assertEqual(status, 130)
                    if exists:
                        self.assertEqual(target.read_bytes(), b"original report\n")
                    else:
                        self.assertFalse(target.exists())
                    self.assertEqual(output.getvalue(), "")
                    self.assertNotIn('"schema_version"', errors.getvalue())
                    self.assertIn("中断", errors.getvalue())
                    self.assertEqual(list(root.glob(".spaceatlas-*.tmp")), [])

    def test_csv_row_interrupt_never_replaces_existing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "sample.txt").write_bytes(b"abc")
            target = root / "report.csv"
            target.write_bytes(b"original report\n")
            original_fdopen = os.fdopen
            def interrupted_file(*args, **kwargs):
                return InterruptingStream(original_fdopen(*args, **kwargs))
            output, errors = io.StringIO(), io.StringIO()
            with patch("os.fdopen", side_effect=interrupted_file), \
                    redirect_stdout(output), redirect_stderr(errors):
                status = main(["--path", str(source), "--format", "csv",
                               "--output", str(target), "--force"])
            self.assertEqual(target.read_bytes(), b"original report\n")
            self.assertEqual(status, 130)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn('"schema_version"', errors.getvalue())
            self.assertIn("中断", errors.getvalue())
            self.assertEqual(list(root.glob(".spaceatlas-*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
