from contextlib import redirect_stdout, redirect_stderr
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.app_scan import inspect_app
from storage_inspector.domain import InstalledApp
from storage_inspector.scanner import directory_stats, validate_extension_filters
from storage_inspector.windows_inventory import InventoryResult
from test_scan_limits import TrackedEntries


class ExtensionFilterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        (self.root / "child").mkdir(parents=True)
        for name, size in (("README", 2), (".env", 3), ("a.TXT", 4), ("b.txt", 0),
                           ("child/c.csv", 6), ("archive.tar.gz", 8), ("notes.资料", 5), ("cache.tmp", 7)):
            (self.root / name).write_bytes(b"x" * size)

    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_normalization_and_mutual_exclusion(self):
        self.assertEqual(validate_extension_filters(["TXT", ".txt", "csv", ".", "资料", "C++"]),
                         ([".", ".c++", ".csv", ".txt", ".资料"], []))
        self.assertEqual(validate_extension_filters(exclude_ext=("TMP", ".tmp")), ([], [".tmp"]))
        self.assertEqual(validate_extension_filters(), ([], []))
        with self.assertRaises(ValueError):
            validate_extension_filters(["txt"], ["csv"])

    def test_invalid_filters_fail_before_access(self):
        values = ([], "txt", True, [True], [""], [".."], ["tar.gz"], ["*.txt"],
                  ["a/b"], ["a\\b"], [" txt"], ["txt "], ["a,b"], ["a:b"], ["x\n"])
        for valueset in values:
            for option in ("include_ext", "exclude_ext"):
                with self.subTest(value=valueset, option=option), patch.object(Path, "lstat") as probe:
                    with self.assertRaises(ValueError):
                        directory_stats(self.root, **{option: valueset})
                    with self.assertRaises(ValueError):
                        inspect_app(InventoryResult(), "missing", **{option: valueset})
                    probe.assert_not_called()

    def test_include_aggregates_and_events_share_scope_without_reading_contents(self):
        events = []
        with patch.object(Path, "open", side_effect=AssertionError("metadata only")):
            result = directory_stats(self.root, include_ext=["TXT", ".csv"], by_extension=True,
                                     by_directory=True, top_files=10,
                                     on_file=lambda p, info: events.append((p, info.st_size)))
        self.assertEqual((result.file_count, result.logical_bytes), (3, 10))
        self.assertEqual((result.extension_filtered_files, result.extension_filtered_bytes), (5, 25))
        self.assertEqual(result.include_ext, [".csv", ".txt"])
        self.assertTrue(result.partial)
        self.assertEqual({p.name for p, _ in events}, {"a.TXT", "b.txt", "c.csv"})
        for groups in (result.extension_summary, result.directory_summary, result.largest_files):
            self.assertEqual(sum(g["logical_bytes"] for g in groups), 10)

    def test_exclusion_default_and_no_match(self):
        default = directory_stats(self.root)
        self.assertEqual((default.file_count, default.logical_bytes), (8, 35))
        self.assertFalse(default.partial)
        result = directory_stats(self.root, exclude_ext=["TMP"])
        self.assertEqual((result.file_count, result.logical_bytes), (7, 28))
        self.assertEqual((result.extension_filtered_files, result.extension_filtered_bytes), (1, 7))
        self.assertFalse(directory_stats(self.root, exclude_ext=["mp4"]).partial)

    def test_no_suffix_multisuffix_unicode_and_zero_bytes(self):
        for selected, count, size in ((["."], 2, 5), (["gz"], 1, 8), (["资料"], 1, 5)):
            result = directory_stats(self.root, include_ext=selected)
            self.assertEqual((result.file_count, result.logical_bytes), (count, size))
        result = directory_stats(self.root / "b.txt", include_ext=["TXT"])
        self.assertEqual(result.file_count, 1)
        self.assertFalse(result.partial)
        result = directory_stats(self.root / "b.txt", exclude_ext=["txt"])
        self.assertEqual((result.extension_filtered_files, result.extension_filtered_bytes), (1, 0))
        self.assertTrue(result.partial)

    def test_empty_and_missing_root_preserve_status(self):
        empty = self.base / "empty"
        empty.mkdir()
        self.assertFalse(directory_stats(empty, include_ext=["txt"]).partial)
        missing = directory_stats(self.base / "missing", include_ext=["txt"])
        self.assertTrue(missing.partial)
        self.assertEqual((missing.error_count, missing.extension_filtered_files), (1, 0))

    def test_real_hardlink_first_path_classification(self):
        original = self.root / "a.TXT"
        alias = self.root / "alias.bin"
        os.link(original, alias)
        for paths, included, filtered in (([alias, original], 0, 1), ([original, alias], 1, 0)):
            with patch("storage_inspector.scanner.os.scandir", return_value=iter(paths)):
                result = directory_stats(self.root, include_ext=["txt"])
            self.assertEqual((result.file_count, result.extension_filtered_files, result.duplicates),
                             (included, filtered, 1))
            self.assertEqual(result.extension_filtered_bytes, filtered * 4)
            self.assertEqual(result.partial, bool(filtered))

    def test_extension_precedes_size_without_double_count(self):
        result = directory_stats(self.root, include_ext=["txt", "csv"], min_size=4)
        self.assertEqual((result.file_count, result.logical_bytes), (2, 10))
        self.assertEqual((result.extension_filtered_files, result.extension_filtered_bytes), (5, 25))
        self.assertEqual((result.size_filtered_files, result.size_filtered_bytes), (1, 0))

    def test_depth_and_directory_exclusion_do_not_expand_scope(self):
        for options in ({"max_depth": 1}, {"exclude_dirs": ["child"]}):
            result = directory_stats(self.root, include_ext=["csv"], **options)
            self.assertEqual((result.file_count, result.extension_filtered_files), (0, 7))
            self.assertTrue(result.partial)
        result = directory_stats(self.root, include_ext=["txt"], max_depth=0)
        self.assertEqual((result.extension_filtered_files, result.depth_limited_directories), (0, 1))

    def test_count_and_time_limits(self):
        result = directory_stats(self.root, include_ext=["mp4"], max_files=1)
        self.assertEqual(result.extension_filtered_files, 8)
        self.assertIsNone(result.stop_reason)
        result = directory_stats(self.root, include_ext=["txt"], max_files=1)
        self.assertEqual((result.file_count, result.stop_reason), (1, "max_files"))
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            result = directory_stats(self.root, include_ext=["txt"], max_seconds=1)
        self.assertEqual(result.stop_reason, "max_seconds")

    def test_interrupt_closes_iterators(self):
        real_scandir, opened = os.scandir, []
        def track(path):
            entries = TrackedEntries(real_scandir(path))
            opened.append(entries)
            return entries
        def interrupt(path, info):
            raise KeyboardInterrupt
        with patch("storage_inspector.scanner.os.scandir", side_effect=track):
            result = directory_stats(self.root, include_ext=["txt"], on_file=interrupt)
        self.assertEqual(result.stop_reason, "interrupted")
        self.assertTrue(all(entries.closed for entries in opened))

    def test_cli_rejects_inventory_invalid_and_conflicting_flags_before_io(self):
        cases = (["--list-apps", "--include-ext", "txt"],
                 ["--path", str(self.root), "--include-ext", "txt", "--exclude-ext", "csv"],
                 ["--path", str(self.root), "--exclude-ext", "*.txt"])
        for args in cases:
            with self.subTest(args=args), patch("storage_inspector.__main__.discover_inventory") as inv, \
                    patch("storage_inspector.__main__.directory_stats") as scan, \
                    patch("storage_inspector.__main__.ReportOutput") as output, \
                    self.assertRaises(SystemExit) as error:
                self.cli(args + ["--output", str(self.base / "report.json")])
            self.assertEqual(error.exception.code, 2)
            inv.assert_not_called()
            scan.assert_not_called()
            output.assert_not_called()

    def test_all_formats_and_saving_both_filter_modes(self):
        for mode, count, size, filtered in (("--include-ext", 2, 4, 6), ("--exclude-ext", 6, 31, 2)):
            for kind in ("json", "csv", "ndjson"):
                for saved in (False, True):
                    with self.subTest(mode=mode, kind=kind, saved=saved):
                        destination = self.base / f"report{count}.{kind}"
                        args = ["--path", str(self.root), mode, "TXT", "--format", kind]
                        if saved:
                            args += ["--output", str(destination)]
                        code, output, errors = self.cli(args)
                        if saved:
                            self.assertEqual(output, "")
                            output = destination.read_text(encoding="utf-8")
                        if kind == "csv":
                            report = json.loads(errors)
                            rows = list(csv.DictReader(io.StringIO(output)))
                            self.assertEqual((len(rows), sum(int(r["size"]) for r in rows)), (count, size))
                        elif kind == "ndjson":
                            events = [json.loads(line) for line in output.splitlines()]
                            report = events[-1]["report"]
                            self.assertEqual((len(events) - 1, sum(e["size"] for e in events[:-1])), (count, size))
                            self.assertEqual(events[-1]["exit_code"], 2)
                        else:
                            report = json.loads(output)
                        self.assertEqual(code, 2)
                        self.assertEqual((report["file_count"], report["logical_bytes"]), (count, size))
                        self.assertEqual(report["extension_filtered_files"], filtered)

    @unittest.skipUnless(os.name == "nt", "Windows installation paths")
    def test_application_all_formats(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Sample", install_location=str(self.root))])
        for kind in ("json", "csv", "ndjson"):
            with patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
                code, output, errors = self.cli(["--app", "sample", "--include-ext", "txt", "--format", kind])
            report = (json.loads(errors) if kind == "csv" else json.loads(output.splitlines()[-1])["report"]
                      if kind == "ndjson" else json.loads(output))
            self.assertEqual(code, 2)
            self.assertEqual((report["scan"]["file_count"], report["scan"]["logical_bytes"]), (2, 4))
            self.assertEqual(report["scan"]["include_ext"], [".txt"])


if __name__ == "__main__":
    unittest.main()
