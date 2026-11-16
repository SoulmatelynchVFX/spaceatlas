"""Summarize only files already counted by the scanner."""
from dataclasses import dataclass, field


MAX_TREE_DEPTH = 64
NODE_ORDER = {"direct_files": 0, "directory": 1, "other": 2}


def validate_tree_depth(depth):
    if depth is not None and (type(depth) is not int or not 0 <= depth <= MAX_TREE_DEPTH):
        raise ValueError(f"tree_depth 必须为 0 至 {MAX_TREE_DEPTH} 的整数")


@dataclass
class TreeNode:
    name: str
    kind: str = "directory"
    logical_bytes: int = 0
    file_count: int = 0
    children: dict[tuple[str, str], "TreeNode"] = field(default_factory=dict)

    def count_file(self, size):
        self.logical_bytes += size
        self.file_count += 1

    def child(self, kind, name):
        key = (kind, name)
        if key not in self.children:
            self.children[key] = TreeNode(name, kind)
        return self.children[key]

    def add_file(self, relative_path, size, depth):
        self.count_file(size)
        if not relative_path:
            self.kind = "file"
            return
        directories = relative_path[:-1]
        node = self
        for name in directories[:depth]:
            node = node.child("directory", name)
            node.count_file(size)
        if len(directories) > depth:
            node.child("other", "其他").count_file(size)
        else:
            node.child("direct_files", "直属文件").count_file(size)

    def report(self, total_bytes):
        hundredths = ((self.logical_bytes * 20000 + total_bytes) // (2 * total_bytes)
                      if total_bytes else 0)
        whole, fraction = divmod(hundredths, 100)
        children = sorted(
            self.children.values(),
            key=lambda node: (NODE_ORDER[node.kind], -node.logical_bytes, node.name.casefold(), node.name),
        )
        return {
            "name": self.name,
            "kind": self.kind,
            "logical_bytes": self.logical_bytes,
            "file_count": self.file_count,
            "share_percent": f"{whole}.{fraction:02d}",
            "children": [child.report(total_bytes) for child in children],
        }
