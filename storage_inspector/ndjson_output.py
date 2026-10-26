"""Emit metadata events immediately, followed by a versioned scan summary."""
from datetime import datetime, timezone
import json


class NdjsonOutputError(RuntimeError):
    """Writing the destination failed, rather than reading a scan source."""


class NdjsonOutputInterrupted(RuntimeError):
    """A record may be torn; do not append a summary to an interrupted write."""


class NdjsonFileWriter:
    def __init__(self, output, schema_version):
        self.output = output
        self.schema_version = schema_version
        self.files_written = 0
        self.missing_modified = 0

    def _emit(self, event):
        try:
            # ASCII escaping preserves Unicode paths even on legacy Windows streams.
            line = json.dumps({"schema_version": self.schema_version, **event},
                              ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
            if self.output.write(line) != len(line):
                raise OSError("incomplete destination write")
            self.output.flush()
        except KeyboardInterrupt as error:
            # The scanner handles traversal interrupts, but cannot repair a torn line.
            raise NdjsonOutputInterrupted("NDJSON record write interrupted") from error
        except (OSError, UnicodeError, ValueError) as error:
            raise NdjsonOutputError(str(error)) from error

    def write_file(self, path, info):
        try:
            modified = datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
        except (AttributeError, TypeError, ValueError, OverflowError, OSError):
            modified = None
            self.missing_modified += 1
        self._emit({"event": "file", "path": str(path), "size": info.st_size,
                    "modified": modified})
        self.files_written += 1

    def finish(self, report, status):
        report["ndjson"] = {"files_written": self.files_written,
                            "missing_modified": self.missing_modified}
        report["partial"] = report["partial"] or bool(self.missing_modified)
        if self.missing_modified and status == 0:
            status = 2
        self._emit({"event": "summary", "exit_code": status, "report": report})
        return status
