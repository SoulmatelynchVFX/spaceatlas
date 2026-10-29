"""Stream metadata rows separately from the versioned diagnostic report."""
import csv
from datetime import datetime, timezone
import json


class CsvOutputError(RuntimeError):
    """The destination failed, not a file being scanned."""


class CsvOutputInterrupted(RuntimeError):
    """A row may be torn; do not treat this as a reportable scan interrupt."""


class CsvFileWriter:
    def __init__(self, output):
        self.output = output
        self.rows_written = 0
        self.missing_modified = 0
        try:
            if hasattr(output, "reconfigure"):
                output.reconfigure(encoding="utf-8", newline="")
            self.writer = csv.writer(output, lineterminator="\r\n")
            self.writer.writerow(("path", "size", "modified"))
        except (OSError, UnicodeError) as error:
            raise CsvOutputError(str(error)) from error

    def write_file(self, path, info):
        try:
            modified = datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
        except (AttributeError, TypeError, ValueError, OverflowError, OSError):
            modified = ""
            self.missing_modified += 1
        try:
            self.writer.writerow((str(path), info.st_size, modified))
        except KeyboardInterrupt as error:
            # Escape the scanner's traversal-interrupt handler so staged reports
            # are discarded instead of replacing an existing destination.
            raise CsvOutputInterrupted("CSV row write interrupted") from error
        except (OSError, UnicodeError) as error:
            raise CsvOutputError(str(error)) from error
        self.rows_written += 1

    def finish(self, report, diagnostics):
        report["csv"] = {"rows_written": self.rows_written,
                         "missing_modified": self.missing_modified}
        report["partial"] = report["partial"] or bool(self.missing_modified)
        try:
            self.output.flush()
            print(json.dumps(report, ensure_ascii=True), file=diagnostics, flush=True)
        except (OSError, UnicodeError) as error:
            raise CsvOutputError(str(error)) from error
