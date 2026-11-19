"""Ranking options and summaries over the scanner's counted entries."""
from dataclasses import dataclass


def ranking_options(sort, limit, top_files, by_extension, by_directory, by_type=False):
    if sort is not None and sort not in ("size", "count", "name"):
        raise ValueError("sort 必须为 size、count 或 name")
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError("limit 必须是正整数")
    if sort is None and limit is None:
        return None
    if sum((by_extension, by_directory, by_type)) > 1:
        raise ValueError("排序时只选择一种分组")
    if by_extension:
        source = "extension_summary"
    elif by_directory:
        source = "directory_summary"
    elif by_type:
        source = "type_summary"
    else:
        source = "files"
    order = sort or "size"
    if source == "files" and order == "count":
        raise ValueError("count 排序用于扩展名或目录分组")
    if top_files is not None:
        if source != "files" or order != "size":
            raise ValueError("--top-files 只能与文件 size 排序组合")
        if limit is not None and limit != top_files:
            raise ValueError("--limit 与 --top-files 同时指定时必须相等")
        limit = top_files
    if source == "files" and limit is None:
        limit = 10
    return source, order, limit


@dataclass
class FileCandidate:
    size: int
    path: str
    order: str

    def __lt__(self, other):
        # The heap root is always the least preferred retained file.
        if self.order == "name":
            return self.path > other.path
        return (self.size, self.path) < (other.size, other.path)


def ranking_report(options, stats, files):
    source, order, limit = options
    if source == "files":
        entries = [{"path": item.path, "logical_bytes": item.size, "file_count": 1}
                   for item in files]
        entry_count = stats.file_count
    else:
        name = {"extension_summary": "extension", "directory_summary": "path",
                "type_summary": "category"}[source]
        metric = {"size": "logical_bytes", "count": "file_count"}.get(order)
        groups = getattr(stats, source)
        entries = sorted(groups, key=lambda group: (-group[metric], group[name])
                         if metric else (group[name],))
        entry_count = len(entries)
        if limit is not None:
            entries = entries[:limit]
    return {
        "source": source, "sort": order, "limit": limit, "entries": entries,
        "omitted_count": entry_count - len(entries),
        "omitted_file_count": stats.file_count - sum(item["file_count"] for item in entries),
        "omitted_logical_bytes": stats.logical_bytes - sum(item["logical_bytes"] for item in entries),
    }
