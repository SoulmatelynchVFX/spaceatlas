"""Present scan totals without changing the scanner's exact byte accounting."""
from dataclasses import asdict

from .scanner import DirectoryStats


SCAN_NOTE = (
    "logical_bytes 是已观测且硬链接去重后的文件逻辑长度，不是磁盘实际分配量或可清理容量。"
    "logical_mib 仅为 MiB 展示值（1 MiB = 1048576 字节，保留三位小数、四舍五入），计算应使用原始字节数。"
    "跳过、错误、排除、大小/扩展名过滤或上限可能使结果不完整；扫描不是原子快照，期间变化可能造成误差。"
)


def format_logical_mib(logical_bytes: int) -> str:
    """Return fixed three-decimal MiB, rounded half up using integers only."""
    if type(logical_bytes) is not int or logical_bytes < 0:
        raise ValueError("logical_bytes 必须是非负整数")
    thousandths = (logical_bytes * 1000 + 524288) // 1048576
    whole, fraction = divmod(thousandths, 1000)
    return f"{whole}.{fraction:03d}"


def scan_report(stats: DirectoryStats) -> dict:
    """Add derived presentation fields at the report serialization boundary."""
    return {**asdict(stats), "partial": stats.partial,
            "logical_mib": format_logical_mib(stats.logical_bytes)}
