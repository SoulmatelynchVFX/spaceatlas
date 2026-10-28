"""Stage explicit report exports outside scan roots, then publish without truncation."""
import os
from pathlib import Path
import stat
import tempfile

from .scanner import should_skip


class ReportOutputError(RuntimeError):
    """The report destination could not be safely written."""


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ReportOutput:
    def __init__(self, path, scan_roots=(), *, force=False):
        raw = Path(path)
        if ".." in raw.parts:
            raise ReportOutputError("输出路径不能包含 ..，请提供明确路径")
        self.path = raw.absolute()
        if os.name == "nt":
            if self.path.drive.startswith("\\\\") or raw.is_reserved():
                raise ReportOutputError("输出仅支持本地普通文件，不接受网络或设备路径")
            for part in self.path.parts[1:]:
                if part.endswith((".", " ")) or any(c in part for c in ':*?"<>|') or any(ord(c) < 32 for c in part):
                    raise ReportOutputError("输出路径包含不安全的 Windows 文件名或数据流语法")
        try:
            self.roots = [Path(root).resolve() for root in scan_roots]
        except (OSError, RuntimeError) as error:
            raise ReportOutputError(f"无法确认扫描范围：{error}") from error
        self.force = force
        self.stream = None
        self.temporary = None
        self.original = None
        self.parents = None

    def _check(self):
        parents = []
        for parent in reversed(self.path.parents):
            info = parent.lstat()
            if should_skip(info) or not stat.S_ISDIR(info.st_mode):
                raise ReportOutputError("输出的父路径必须是已有普通目录，不能经过链接、重解析点或离线项")
            parents.append((str(parent), info.st_dev, info.st_ino))
        if self.parents is not None and parents != self.parents:
            raise ReportOutputError("写出期间输出父目录发生变化，已取消保存")
        try:
            resolved = self.path.resolve()
        except (OSError, RuntimeError) as error:
            raise ReportOutputError(f"无法确认输出路径：{error}") from error
        if any(resolved == root or root in resolved.parents for root in self.roots):
            raise ReportOutputError("报告必须写到扫描范围之外，不能覆盖扫描源或保存到扫描目录内")
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return parents, None
        if should_skip(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ReportOutputError("输出目标必须是普通单链接文件，拒绝目录、链接、重解析点和特殊文件")
        if not self.force:
            raise ReportOutputError("输出文件已存在；选择新路径或明确使用 --force")
        return parents, _signature(info)

    def __enter__(self):
        try:
            self.parents, self.original = self._check()
            descriptor, name = tempfile.mkstemp(prefix=".spaceatlas-", suffix=".tmp", dir=self.path.parent)
            self.temporary = Path(name)
            try:
                self.stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
            except BaseException:
                os.close(descriptor)
                raise
            return self
        except BaseException as error:
            self._cleanup()
            if isinstance(error, (OSError, UnicodeError)):
                raise ReportOutputError(str(error)) from error
            raise

    def commit(self):
        try:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()
            _, current = self._check()
            if current != self.original:
                raise ReportOutputError("写出期间目标文件发生变化，已取消保存")
            if self.original is not None:
                os.replace(self.temporary, self.path)
            elif os.name == "nt":
                # Windows rename fails if the destination appeared concurrently.
                os.rename(self.temporary, self.path)
            else:
                # POSIX rename overwrites; linking instead gives atomic no-clobber.
                os.link(self.temporary, self.path)
                self.temporary.unlink()
            self.temporary = None
        except OSError as error:
            raise ReportOutputError(str(error)) from error

    def _cleanup(self):
        try:
            if self.stream is not None and not self.stream.closed:
                self.stream.close()
        finally:
            if self.temporary is not None:
                self.temporary.unlink(missing_ok=True)
                self.temporary = None

    def __exit__(self, kind, error, traceback):
        try:
            self._cleanup()
        except OSError as cleanup_error:
            raise ReportOutputError(f"临时报告清理失败：{cleanup_error}") from cleanup_error
        if isinstance(error, (OSError, UnicodeError)):
            raise ReportOutputError(str(error)) from error
        return False
