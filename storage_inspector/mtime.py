"""Classify modification times against a single UTC scan reference."""
from datetime import datetime, timedelta, timezone
import math


NS_PER_SECOND = 1_000_000_000
DAY_NS = 86_400 * NS_PER_SECOND
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MIN_UTC_NS = (datetime.min.replace(tzinfo=timezone.utc) - EPOCH).days * DAY_NS
MAX_UTC_NS = ((datetime.max.replace(tzinfo=timezone.utc) - EPOCH).days + 1) * DAY_NS - 1
MTIME_BUCKETS = ("lt_30d", "30_to_lt_180d", "180_to_365d", "gt_365d", "future", "unknown")


def format_reference_utc(reference_ns: int) -> str:
    seconds, nanoseconds = divmod(reference_ns, NS_PER_SECOND)
    whole = EPOCH + timedelta(seconds=seconds)
    return f"{whole.isoformat(timespec='seconds').removesuffix('+00:00')}.{nanoseconds:09d}Z"


def modification_bucket(info, reference_ns: int) -> str:
    try:
        modified_ns = getattr(info, "st_mtime_ns", None)
        if modified_ns is None:
            seconds = info.st_mtime
            if type(seconds) is int:
                modified_ns = seconds * NS_PER_SECOND
            elif type(seconds) is float and math.isfinite(seconds):
                numerator, denominator = seconds.as_integer_ratio()
                modified_ns = numerator * NS_PER_SECOND // denominator
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        return "unknown"
    if type(modified_ns) is not int or not MIN_UTC_NS <= modified_ns <= MAX_UTC_NS:
        return "unknown"
    age = reference_ns - modified_ns
    if age < 0:
        return "future"
    if age < 30 * DAY_NS:
        return "lt_30d"
    if age < 180 * DAY_NS:
        return "30_to_lt_180d"
    if age <= 365 * DAY_NS:
        return "180_to_365d"
    return "gt_365d"
