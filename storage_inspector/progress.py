"""Optional bounded-frequency diagnostics, separate from report serialization."""
import json
import time


class ProgressOutputError(Exception):
    pass


class ProgressReporter:
    def __init__(self, stream):
        self.stream = stream
        self.last_update = None

    def update(self, stats, *, finished=False):
        now = time.monotonic()
        if not finished and self.last_update is not None and now - self.last_update < 1:
            return
        event = {
            "state": "finished" if finished else "scanning",
            "file_count": stats.file_count,
            "logical_bytes": stats.logical_bytes,
            "error_count": stats.error_count,
            "skipped": stats.skipped,
            "duplicates": stats.duplicates,
            "partial": stats.partial,
            "stop_reason": stats.stop_reason,
        }
        try:
            print("progress " + json.dumps(event, ensure_ascii=True), file=self.stream, flush=True)
        except (OSError, UnicodeError) as error:
            raise ProgressOutputError("progress diagnostics write failed") from error
        self.last_update = now
