"""Read file metadata only; never follow discovered links or open file contents."""
from dataclasses import dataclass, field
import heapq
import math
import os
import re
from pathlib import Path
import stat
import time


# Reparse points include Windows junctions and many cloud placeholders.
SKIP_ATTRIBUTE_REASONS = (
    (0x400, "reparse_point"),
    (0x1000, "offline"),
    (0x40000, "recall_on_open"),
    (0x400000, "recall_on_data_access"),
)
MAX_ERROR_DETAILS = 100
MAX_SKIP_DETAILS = 100


@dataclass
class DirectoryStats:
    path: str
    logical_bytes: int = 0
    file_count: int = 0
    skipped: int = 0
    duplicates: int = 0
    error_count: int = 0
    errors: list[dict] = field(default_factory=list)
    stop_reason: str | None = None
    largest_files: list[dict] = field(default_factory=list)
    excluded_directories: int = 0
    exclude_dirs: list[str] = field(default_factory=list)
    extension_summary: list[dict] = field(default_factory=list)
    directory_summary: list[dict] = field(default_factory=list)
    skip_reason_counts: dict[str, int] = field(default_factory=dict)
    skip_details: list[dict] = field(default_factory=list)
    skip_details_omitted: int = 0
    max_depth: int | None = None
    depth_limited_directories: int = 0
    min_size: int | None = None
    size_filtered_files: int = 0
    size_filtered_bytes: int = 0

    @property
    def partial(self):
        return bool(self.error_count or self.skipped or self.stop_reason or
                    self.excluded_directories or self.depth_limited_directories or
                    self.size_filtered_files)

    def record_error(self, path, error):
        self.error_count += 1
        if len(self.errors) < MAX_ERROR_DETAILS:
            self.errors.append({"path": str(path), "message": str(error)})

    def record_skip(self, path, reason):
        self.skipped += 1
        self.skip_reason_counts[reason] = self.skip_reason_counts.get(reason, 0) + 1
        if len(self.skip_details) < MAX_SKIP_DETAILS:
            self.skip_details.append({"path": str(path), "reason": reason})
        else:
            self.skip_details_omitted += 1


def skip_reason(info):
    """Return one primary reason without following a link or reading file data."""
    if stat.S_ISLNK(info.st_mode):
        return "symbolic_link"
    attributes = getattr(info, "st_file_attributes", 0)
    for flag, reason in SKIP_ATTRIBUTE_REASONS:
        if attributes & flag:
            return reason
    return None


def should_skip(info):
    return skip_reason(info) is not None


def validate_limits(max_files=None, max_seconds=None):
    if max_files is not None and (type(max_files) is not int or max_files <= 0):
        raise ValueError("max_files 必须是正整数")
    if max_seconds is not None and (
        type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or max_seconds <= 0
    ):
        raise ValueError("max_seconds 必须是有限正数")


def validate_max_depth(max_depth=None):
    if max_depth is not None and (type(max_depth) is not int or max_depth < 0):
        raise ValueError("max_depth 必须是非负整数")


def validate_min_size(min_size=None):
    if min_size is not None and (type(min_size) is not int or min_size < 0):
        raise ValueError("min_size 必须是非负整数字节数")


def parse_min_size(value):
    """CLI bytes or binary K/M/G units, with no float conversion."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+[KMGkmg]?", value) is None:
        raise ValueError("min-size 必须为非负整数，可带 K/M/G 后缀（1024 进制）")
    suffix = value[-1].upper()
    power = {"K": 1, "M": 2, "G": 3}.get(suffix, 0)
    return int(value[:-1] if power else value) * (1024 ** power)


def validate_top_files(top_files=None):
    if top_files is not None and (type(top_files) is not int or top_files <= 0):
        raise ValueError("top_files 必须是正整数")


def validate_exclude_dirs(exclude_dirs=None):
    if exclude_dirs is None:
        return []
    if not isinstance(exclude_dirs, (list, tuple)):
        raise ValueError("exclude_dirs 必须是目录名列表")
    for name in exclude_dirs:
        if (not isinstance(name, str) or not name or name in (".", "..")
                or name.endswith((".", " ")) or any(ord(char) < 32 for char in name)
                or any(char in name for char in '/\\:*?"<>|')):
            raise ValueError("排除目录必须是单个目录名，不接受路径、通配符或末尾点/空格")
    return sorted({name.casefold() for name in exclude_dirs})


def directory_stats(path: Path, *, max_files=None, max_seconds=None, top_files=None,
                    exclude_dirs=None, by_extension=False, by_directory=False,
                    on_file=None, max_depth=None, min_size=None) -> DirectoryStats:
    validate_limits(max_files, max_seconds)
    validate_max_depth(max_depth)
    validate_min_size(min_size)
    validate_top_files(top_files)
    excluded_names = validate_exclude_dirs(exclude_dirs)
    deadline = time.monotonic() + max_seconds if max_seconds is not None else None
    # abspath normalizes the supplied path without resolving symlinks.
    root = Path(os.path.abspath(path))
    result = DirectoryStats(str(root), exclude_dirs=excluded_names, max_depth=max_depth,
                            min_size=min_size)
    excluded_lookup = set(excluded_names)
    # Keep only active directory iterators, rather than collecting a wide directory
    # before examining its files. Close every iterator on early termination too.
    # The third value is the depth of entries yielded by this iterator.
    stack = [(root, iter((root,)), 0)]
    seen = set()
    largest = []
    extensions = {}
    directories = {}
    try:
        while stack:
            if deadline is not None and time.monotonic() >= deadline:
                result.stop_reason = "max_seconds"
                break
            if max_files is not None and result.file_count >= max_files:
                result.stop_reason = "max_files"
                break
            parent, entries, depth = stack[-1]
            try:
                entry = next(entries)
            except (StopIteration, OSError) as error:
                stack.pop()
                close = getattr(entries, "close", None)
                if close:
                    close()
                if isinstance(error, OSError):
                    result.record_error(parent, error)
                continue
            current = entry if isinstance(entry, Path) else Path(entry.path)
            file_record = None
            try:
                info = current.lstat()
                reason = skip_reason(info)
                if reason is not None:
                    result.record_skip(current, reason)
                    continue
                if stat.S_ISDIR(info.st_mode):
                    # The explicitly selected root is never excluded by its own name.
                    if current != root and current.name.casefold() in excluded_lookup:
                        result.excluded_directories += 1
                        continue
                    if max_depth is not None and depth >= max_depth:
                        # Unopened contents are unknown, not zero-sized.
                        result.depth_limited_directories += 1
                        continue
                    stack.append((current, os.scandir(current), depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    identity = (info.st_dev, info.st_ino)
                    if info.st_ino and identity in seen:
                        result.duplicates += 1
                        continue
                    if info.st_ino:
                        seen.add(identity)
                    if min_size is not None and info.st_size < min_size:
                        result.size_filtered_files += 1
                        result.size_filtered_bytes += info.st_size
                        continue
                    result.logical_bytes += info.st_size
                    result.file_count += 1
                    if by_directory:
                        if current == root:
                            group_path, kind = root, "file"
                        elif current.parent == root:
                            group_path, kind = root, "direct_files"
                        else:
                            group_path = root / current.relative_to(root).parts[0]
                            kind = "directory"
                        key = str(group_path)
                        group = directories.setdefault(key, {
                            "path": key, "kind": kind, "logical_bytes": 0, "file_count": 0,
                        })
                        group["logical_bytes"] += info.st_size
                        group["file_count"] += 1
                    if by_extension:
                        extension = current.suffix.casefold()
                        group = extensions.setdefault(extension, {
                            "extension": extension, "logical_bytes": 0, "file_count": 0,
                        })
                        group["logical_bytes"] += info.st_size
                        group["file_count"] += 1
                    if top_files is not None:
                        candidate = (info.st_size, str(current))
                        if len(largest) < top_files:
                            heapq.heappush(largest, candidate)
                        else:
                            heapq.heappushpop(largest, candidate)
                    file_record = (current, info)
                else:
                    result.record_skip(current, "special_file")
            except OSError as error:
                result.record_error(current, error)
            # Destination errors must not be mistaken for unreadable source files.
            if file_record is not None and on_file is not None:
                on_file(*file_record)
    except KeyboardInterrupt:
        # Preserve observations without mistaking an interrupted walk for completion.
        result.stop_reason = "interrupted"
    finally:
        for _, entries, _ in reversed(stack):
            close = getattr(entries, "close", None)
            if close:
                close()
    result.largest_files = [
        {"path": path, "logical_bytes": size}
        for size, path in sorted(largest, reverse=True)
    ]
    result.extension_summary = sorted(
        extensions.values(), key=lambda group: (-group["logical_bytes"], group["extension"])
    )
    result.directory_summary = sorted(
        directories.values(), key=lambda group: (-group["logical_bytes"], group["path"])
    )
    return result
