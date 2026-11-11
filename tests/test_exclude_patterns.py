from contextlib import redirect_stderr, redirect_stdout
import csv
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.__main__ import main
from storage_inspector.app_scan import inspect_app
from storage_inspector.domain import InstalledApp
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult


class ExcludePatternTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        for name, size in (("log.TMP", 3), ("sub/deep.tmp", 5), ("sub/KEEP.txt", 7),
                           ("cache/private.txt", 11), ("cache-old/ok.txt", 13),
                           ("资料/片段1.log", 17), ("资料/片段12.log", 19)):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * size)

    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main(args)
        return status, output.getvalue(), errors.getvalue()

    def test_star_is_anchored_and_does_not_cross_directories(self):
        result = directory_stats(self.root, exclude_patterns=["*.TMP"], top_files=10)
        self.assertEqual((result.file_count, result.logical_bytes, result.pattern_excluded_files), (6, 72, 1))
        self.assertIn(str(self.root / "sub/deep.tmp"), {x["path"] for x in result.largest_files})

    def test_double_star_matches_zero_or_multiple_segments(self):
        deep = self.root / "sub/more/levels/a.tmp"
        deep.parent.mkdir(parents=True)
        deep.write_bytes(b"a")
        for pattern in ("**/*.tmp", "**/**/*.tmp"):
            with self.subTest(pattern=pattern):
                result = directory_stats(self.root, exclude_patterns=[pattern])
                self.assertEqual((result.file_count, result.logical_bytes, result.pattern_excluded_files), (5, 67, 3))

    def test_normalizes_separators_case_unicode_and_duplicates(self):
        result = directory_stats(self.root, exclude_patterns=[r"SUB\*.TMP", "sub/*.tmp", "资料/片段?.log"])
        self.assertEqual(result.exclude_patterns, ["sub/*.tmp", "资料/片段?.log"])
        self.assertEqual((result.file_count, result.logical_bytes, result.pattern_excluded_files), (5, 53, 2))

    def test_pruned_directory_is_not_enumerated_or_read(self):
        excluded = self.root / "cache"
        real_scandir, real_lstat = os.scandir, Path.lstat
        opened = []
        def track(path):
            opened.append(path)
            return real_scandir(path)
        def metadata(path, *args, **kwargs):
            self.assertNotIn(excluded, path.parents)
            return real_lstat(path, *args, **kwargs)
        with patch("storage_inspector.scanner.os.scandir", side_effect=track), \
                patch.object(Path, "lstat", metadata), patch.object(Path, "open", side_effect=AssertionError("metadata only")):
            result = directory_stats(self.root, exclude_patterns=["cache/**", "cache/*"])
        self.assertNotIn(excluded, opened)
        self.assertIn(self.root / "cache-old", opened)
        self.assertEqual((result.pattern_excluded_directories, result.pattern_excluded_files), (1, 0))
        self.assertEqual((result.file_count, result.logical_bytes), (6, 64))
        self.assertTrue(result.partial)

    def test_directory_name_wins_before_pattern_and_depth(self):
        result = directory_stats(self.root, exclude_dirs=["cache"],
                                 exclude_patterns=["cache", "sub", "*.tmp"], max_depth=1)
        self.assertEqual((result.excluded_directories, result.pattern_excluded_directories,
                          result.depth_limited_directories, result.pattern_excluded_files), (1, 1, 2, 1))
        self.assertEqual(result.file_count, 0)

    def test_explicit_directory_root_is_kept_and_file_root_can_match(self):
        chosen = self.root / "cache"
        result = directory_stats(chosen, exclude_dirs=["cache"], exclude_patterns=["cache"])
        self.assertEqual(result.logical_bytes, 11)
        self.assertFalse(result.partial)
        excluded = directory_stats(self.root / "log.TMP", exclude_patterns=["*.tmp"], max_depth=0)
        self.assertEqual((excluded.file_count, excluded.pattern_excluded_files), (0, 1))
        self.assertTrue(excluded.partial)

    def test_safety_classification_is_not_masked_by_patterns(self):
        real_lstat = Path.lstat
        for info in (SimpleNamespace(st_mode=stat.S_IFLNK),
                     SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400),
                     SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x1000)):
            target = self.root / "cache"
            def metadata(path, *args, **kwargs):
                return info if path == target else real_lstat(path, *args, **kwargs)
            with self.subTest(info=info), patch.object(Path, "lstat", metadata):
                result = directory_stats(self.root, exclude_patterns=["cache/**"])
            self.assertEqual((result.skipped, result.pattern_excluded_directories, result.pattern_excluded_files), (1, 0, 0))
            self.assertEqual(result.file_count, 6)

    def test_unexcluded_real_hard_link_alias_still_counts(self):
        original = self.root / "log.TMP"
        alias = self.root / "keep.bin"
        os.link(original, alias)
        for paths in ([original, alias], [alias, original]):
            with patch("storage_inspector.scanner.os.scandir", return_value=iter(paths)):
                result = directory_stats(self.root, exclude_patterns=["*.tmp"], top_files=1)
            self.assertEqual((result.file_count, result.logical_bytes, result.duplicates, result.pattern_excluded_files), (1, 3, 0, 1))
            self.assertEqual(result.largest_files[0]["path"], str(alias))

    def test_extension_size_and_group_totals_do_not_double_count(self):
        events = []
        result = directory_stats(self.root, exclude_patterns=["cache/**", "**/*.tmp"], include_ext=["txt"],
                                 min_size=8, by_directory=True, by_extension=True, top_files=2,
                                 on_file=lambda p, info: events.append((p, info.st_size)))
        self.assertEqual((result.pattern_excluded_directories, result.pattern_excluded_files,
                          result.extension_filtered_files, result.size_filtered_files), (1, 2, 2, 1))
        self.assertEqual((result.file_count, result.logical_bytes), (1, 13))
        self.assertEqual(events, [(self.root / "cache-old/ok.txt", 13)])
        for groups in (result.largest_files, result.directory_summary, result.extension_summary):
            self.assertEqual(sum(g["logical_bytes"] for g in groups), 13)

    def test_default_no_match_and_limits(self):
        for patterns in (None, [], ["*.mp4"]):
            result = directory_stats(self.root, exclude_patterns=patterns)
            self.assertEqual((result.file_count, result.logical_bytes), (7, 75))
            self.assertFalse(result.partial)
        entries = iter([self.root / "log.TMP", self.root / "sub/KEEP.txt"])
        with patch("storage_inspector.scanner.os.scandir", return_value=entries):
            result = directory_stats(self.root, exclude_patterns=["*.tmp"], max_files=1)
        self.assertEqual((result.file_count, result.pattern_excluded_files, result.stop_reason), (1, 1, "max_files"))
        with patch("storage_inspector.scanner.time.monotonic", side_effect=[0, 2]):
            result = directory_stats(self.root, exclude_patterns=["**"], max_seconds=1)
        self.assertEqual((result.pattern_excluded_files, result.stop_reason), (0, "max_seconds"))

    def test_invalid_patterns_rejected_before_io(self):
        invalid = ("tmp", True, [None], [""], ["."], ["../*"], ["a/./b"], ["/a"], [r"\a"],
                   ["C:a"], [r"C:\a"], [r"\\host\share\*"], ["a//b"], ["a/"], ["a**b"],
                   ["***"], ["a[bc]"], ["{a,b}"], ["a\x00"], ["a "], ["a."])
        for patterns in invalid:
            with self.subTest(patterns=patterns), patch.object(Path, "lstat") as probe:
                with self.assertRaises(ValueError):
                    directory_stats(self.root, exclude_patterns=patterns)
                with self.assertRaises(ValueError):
                    inspect_app(InventoryResult(), "missing", exclude_patterns=patterns)
                probe.assert_not_called()

    def test_cli_rejects_inventory_and_invalid_before_output(self):
        for args in (["--list-apps", "--exclude-pattern", "**"],
                     ["--app", "sample", "--exclude-pattern", "../*"]):
            with self.subTest(args=args), patch("storage_inspector.__main__.discover_inventory") as inv, \
                    patch("storage_inspector.__main__.ReportOutput") as output, self.assertRaises(SystemExit) as error:
                self.cli(args + ["--output", str(self.base / "result.json")])
            self.assertEqual(error.exception.code, 2)
            inv.assert_not_called()
            output.assert_not_called()

    def test_path_output_formats_and_safe_save(self):
        for kind in ("json", "csv", "ndjson"):
            for saved in (False, True):
                with self.subTest(kind=kind, saved=saved):
                    destination = self.base / f"result.{kind}"
                    args = ["--path", str(self.root), "--exclude-pattern", "cache/**", "--exclude-pattern", "**/*.tmp",
                            "--exclude-pattern", "资料/片段?.log", "--format", kind]
                    if saved:
                        args += ["--output", str(destination)]
                    code, output, errors = self.cli(args)
                    if saved:
                        self.assertEqual(output, "")
                        output = destination.read_text(encoding="utf-8")
                    if kind == "csv":
                        report = json.loads(errors)
                        self.assertEqual(sorted(int(row["size"]) for row in csv.DictReader(io.StringIO(output))), [7, 13, 19])
                    elif kind == "ndjson":
                        events = [json.loads(line) for line in output.splitlines()]
                        self.assertEqual(sorted(e["size"] for e in events[:-1]), [7, 13, 19])
                        self.assertEqual(events[-1]["exit_code"], 2)
                        report = events[-1]["report"]
                    else:
                        report = json.loads(output)
                    self.assertEqual(code, 2)
                    self.assertEqual((report["file_count"], report["logical_bytes"]), (3, 39))
                    self.assertEqual((report["pattern_excluded_directories"], report["pattern_excluded_files"]), (1, 3))
                    self.assertEqual(report["exclude_patterns"], ["**/*.tmp", "cache/**", "资料/片段?.log"])
                    self.assertTrue(report["partial"])

    @unittest.skipUnless(os.name == "nt", "Windows installation paths")
    def test_app_propagates_root_relative_patterns(self):
        inventory = InventoryResult(applications=[InstalledApp("sample", "Sample", install_location=str(self.root))])
        with patch("storage_inspector.__main__.discover_inventory", return_value=inventory):
            code, output, errors = self.cli(["--app", "sample", "--exclude-pattern", r"SUB\**"])
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual((report["scan"]["logical_bytes"], report["scan"]["pattern_excluded_directories"]), (63, 1))
        self.assertEqual(report["scan"]["exclude_patterns"], ["sub/**"])


if __name__ == "__main__":
    unittest.main()
