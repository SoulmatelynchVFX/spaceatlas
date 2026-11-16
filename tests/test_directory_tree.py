import csv
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
from storage_inspector.scanner import directory_stats
from storage_inspector.windows_inventory import InventoryResult


class DirectoryTreeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))

    def file(self, path, size):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"x" * size)
        return target

    def cli(self, *args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(args))
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_partition(self, node):
        if node["kind"] == "directory":
            for key in ("file_count", "logical_bytes"):
                self.assertEqual(node[key], sum(child[key] for child in node["children"]))
            for child in node["children"]:
                self.assert_partition(child)
        else:
            self.assertEqual(node["children"], [])

    def test_nested_counts_and_folded_file_entries(self):
        self.file("root", 2)
        self.file("a/file", 3)
        self.file("a/b/file", 4)
        self.file("a/b/c/file", 1)
        report = directory_stats(self.root, tree_depth=1)
        tree = report.directory_tree
        self.assertFalse(report.partial)
        self.assertEqual((tree["logical_bytes"], tree["file_count"], tree["share_percent"]), (10, 4, "100.00"))
        root_files, directory = tree["children"]
        self.assertEqual((root_files["kind"], root_files["logical_bytes"]), ("direct_files", 2))
        self.assertEqual(directory["name"], "a")
        direct, folded = directory["children"]
        self.assertEqual((direct["kind"], direct["share_percent"]), ("direct_files", "30.00"))
        self.assertEqual((folded["kind"], folded["file_count"], folded["logical_bytes"], folded["share_percent"]),
                         ("other", 2, 5, "50.00"))
        self.assert_partition(tree)

    def test_zero_depth_folds_directories_but_not_root_files(self):
        self.file("root", 1)
        self.file("其他/file", 2)
        tree = directory_stats(self.root, tree_depth=0).directory_tree
        self.assertEqual([child["kind"] for child in tree["children"]], ["direct_files", "other"])
        direct, other = tree["children"]
        self.assertEqual((direct["share_percent"], other["share_percent"]), ("33.33", "66.67"))
        self.assert_partition(tree)

    def test_labels_and_sibling_order(self):
        self.file("beta/f", 2)
        self.file("Alpha/f", 2)
        self.file("其他/f", 3)
        self.file("其他/deeper/f", 1)
        self.file("empty", 0)
        tree = directory_stats(self.root, tree_depth=1).directory_tree
        direct, other_directory, alpha, beta = tree["children"]
        self.assertEqual((direct["kind"], direct["file_count"]), ("direct_files", 1))
        self.assertEqual((other_directory["name"], other_directory["kind"]), ("其他", "directory"))
        self.assertEqual(other_directory["children"][-1]["kind"], "other")
        self.assertEqual([alpha["name"], beta["name"]], ["Alpha", "beta"])

    def test_hard_link_and_filters_preserve_observed_scope(self):
        source = self.file("a/file.dat", 11)
        os.link(source, self.root / "alias.dat")
        self.file("a/deep/unopened.dat", 56)
        self.file("cache/excluded.dat", 40)
        self.file("small.dat", 1)
        self.file("extension.bin", 30)
        report = directory_stats(self.root, tree_depth=1, max_depth=2, min_size=2,
                                 exclude_dirs=["cache"], include_ext=["dat"])
        self.assertTrue(report.partial)
        self.assertEqual((report.file_count, report.logical_bytes, report.duplicates), (1, 11, 1))
        self.assertEqual((report.depth_limited_directories, report.excluded_directories), (1, 1))
        self.assertEqual((report.directory_tree["file_count"], report.directory_tree["logical_bytes"]), (1, 11))
        self.assert_partition(report.directory_tree)

    def test_default_empty_and_explicit_file(self):
        stats = directory_stats(self.root, tree_depth=3)
        self.assertEqual(stats.tree_depth, 3)
        self.assertIsNone(stats.directory_tree)
        file = self.file("zero.dat", 0)
        stats = directory_stats(file)
        self.assertIsNone(stats.tree_depth)
        self.assertIsNone(stats.directory_tree)
        tree = directory_stats(file, tree_depth=0).directory_tree
        self.assertEqual((tree["name"], tree["kind"], tree["file_count"], tree["share_percent"], tree["children"]),
                         ("zero.dat", "file", 1, "0.00", []))

    def test_file_limit_only_rolls_up_counted_file(self):
        self.file("a/f", 3)
        self.file("b/f", 6)
        stats = directory_stats(self.root, tree_depth=0, max_files=1)
        self.assertEqual(stats.stop_reason, "max_files")
        self.assertEqual(stats.directory_tree["children"][0]["logical_bytes"], stats.logical_bytes)
        self.assertEqual(stats.directory_tree["children"][0]["file_count"], 1)

    def test_cli_reports_same_tree_in_all_formats(self):
        self.file("a/f", 7)
        args = ("--path", str(self.root), "--tree-depth", "2")
        status, out, _ = self.cli(*args)
        self.assertEqual(status, 0)
        expected = json.loads(out)["directory_tree"]
        # Default JSON formatting keeps its fixed two-space indentation.
        self.assertIn('\n  "directory_tree": {\n    "name":', out)
        for output_format in ("csv", "ndjson"):
            with self.subTest(format=output_format):
                status, out, err = self.cli(*args, "--format", output_format)
                self.assertEqual(status, 0)
                if output_format == "csv":
                    self.assertEqual(next(csv.reader(StringIO(out))), ["path", "size", "modified"])
                    report = json.loads(err)
                else:
                    event, summary = [json.loads(line) for line in out.splitlines()]
                    self.assertEqual(set(event), {"schema_version", "event", "path", "size", "modified"})
                    report = summary["report"]
                self.assertEqual(report["directory_tree"], expected)

    @unittest.skipUnless(os.name == "nt", "Windows app scan")
    def test_application_tree(self):
        self.file("dir/f", 3)
        app = InstalledApp("fixture", "Fixture", install_location=str(self.root))
        with patch("storage_inspector.__main__.discover_inventory", return_value=InventoryResult([app])):
            status, out, _ = self.cli("--app", "fixture", "--tree-depth", "0")
        self.assertEqual(status, 0)
        report = json.loads(out)
        self.assertEqual(report["scan"]["tree_depth"], 0)
        self.assertEqual(report["scan"]["directory_tree"]["children"][0]["kind"], "other")

    def test_invalid_depth_and_inventory_rejected_before_io(self):
        with patch("storage_inspector.__main__.directory_stats") as scan, \
                patch("storage_inspector.__main__.discover_inventory") as discover:
            for args in (("--path", str(self.root), "--tree-depth", "-1"),
                         ("--path", str(self.root), "--tree-depth", "65"),
                         ("--list-apps", "--tree-depth", "0")):
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    self.cli(*args)
                self.assertEqual(error.exception.code, 2)
        scan.assert_not_called()
        discover.assert_not_called()
