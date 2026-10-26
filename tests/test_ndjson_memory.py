"""Measure writer storage separately from native path caches and identity deduplication."""
import gc
import os
from pathlib import Path
import stat
import tracemalloc
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from storage_inspector.ndjson_output import NdjsonFileWriter
from storage_inspector.scanner import directory_stats


class DiscardingOutput:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


class NdjsonMemoryTests(unittest.TestCase):
    OUTPUT_GROWTH_ALLOWANCE = 512 * 1024

    def measure_writer(self, count, writer_type=NdjsonFileWriter):
        # Plain strings isolate the writer from pathlib's process-wide intern table.
        # Generate inputs on demand; neither the input nor the destination stores rows.
        gc.collect()
        tracemalloc.start()
        try:
            writer = writer_type(DiscardingOutput(), 1)
            info = SimpleNamespace(st_size=1, st_mtime=0)
            for index in range(count):
                writer.write_file(f"C:/synthetic/{index:08d}.txt", info)
            writer.finish({"partial": False, "file_count": count}, 0)
            peak = tracemalloc.get_traced_memory()[1]
            self.assertEqual(writer.files_written, count)
        finally:
            tracemalloc.stop()
        return peak

    def assert_bounded_writer(self, writer_type=NdjsonFileWriter):
        peaks = [self.measure_writer(count, writer_type) for count in (1000, 100000)]
        print(f"NDJSON writer peak bytes (1000 / 100000), {writer_type.__name__}: {peaks}", flush=True)
        self.assertLess(peaks[1], peaks[0] + self.OUTPUT_GROWTH_ALLOWANCE)

    def measure_scan(self, count, identities, emit):
        root = Path(os.path.abspath("synthetic-ndjson-memory"))
        def metadata(path):
            if path == root:
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            return SimpleNamespace(st_mode=stat.S_IFREG, st_dev=1,
                                   st_ino=int(path.name) + 1 if identities else 0,
                                   st_size=1, st_mtime=0)
        def entries(path):
            return (SimpleNamespace(path=str(path / str(index))) for index in range(count))
        # Replace callables directly: Mock call histories would grow with the input.
        with patch.object(Path, "lstat", new=metadata), \
                patch("storage_inspector.scanner.os.scandir", new=entries):
            gc.collect()
            tracemalloc.start()
            try:
                writer = NdjsonFileWriter(DiscardingOutput(), 1)
                result = directory_stats(root, on_file=writer.write_file if emit else None)
                if emit:
                    writer.finish({"partial": result.partial, "file_count": result.file_count}, 0)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        self.assertEqual(writer.files_written, count if emit else 0)
        self.assertEqual(result.file_count, count)
        self.assertEqual(result.logical_bytes, count)
        print(f"NDJSON scan peak bytes: count={count}, identities={identities}, "
              f"emit={emit}, peak={peak}", flush=True)
        return peak

    def test_writer_storage_is_bounded_for_100000_records(self):
        self.assert_bounded_writer()

    def test_writer_guard_rejects_accumulating_records(self):
        # Mutation control: the exact same assertion must catch a real retained list.
        class RetainingWriter(NdjsonFileWriter):
            def __init__(self, output, schema_version):
                super().__init__(output, schema_version)
                self.records = []

            def _emit(self, event):
                self.records.append(event)
                super()._emit(event)

        with self.assertRaises(AssertionError):
            self.assert_bounded_writer(RetainingWriter)

    def test_native_scan_baseline_and_exact_identity_cost_for_100000_records(self):
        # Observe native pathlib cache allocations; do not disable sys.intern or
        # attribute the entire no-identity scan peak to the output writer.
        for emit in (False, True):
            for count in (1000, 100000):
                self.measure_scan(count, False, emit)
        exact_index = [self.measure_scan(count, True, True) for count in (1000, 100000)]
        # Exact deduplication has a real growing index. Neither these totals nor
        # differences between peaks from different runs are writer-only memory.
        self.assertGreater(exact_index[1], exact_index[0] + 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
