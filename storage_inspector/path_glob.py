"""Match already visited relative path components without touching the filesystem."""
from fnmatch import fnmatchcase


def validate_exclude_patterns(exclude_patterns=None):
    if exclude_patterns is None:
        return []
    if not isinstance(exclude_patterns, (list, tuple)):
        raise ValueError("exclude_patterns 必须是通配符列表")
    normalized = set()
    for pattern in exclude_patterns:
        if (not isinstance(pattern, str) or not pattern
                or any(ord(char) < 32 or char in ':"<>|[]{}' for char in pattern)):
            raise ValueError("排除通配符只接受相对路径和 *、?、整段 **")
        parts = pattern.replace("\\", "/").split("/")
        if any(not part or part in (".", "..") or part.endswith((".", " "))
               or ("**" in part and part != "**") for part in parts):
            raise ValueError("排除通配符不能包含绝对路径、空段、.、.. 或非整段 **")
        normalized.add("/".join(parts).casefold())
    return sorted(normalized)


def matches_any(patterns, relative_parts):
    """Whole-path matching; ordinary wildcards never see path separators."""
    parts = tuple(part.casefold() for part in relative_parts)
    length = len(parts)
    for pattern in patterns:
        positions = {0}
        for segment in pattern:
            if segment == "**":
                # Any position at or beyond the earliest reachable one is reachable.
                positions = range(min(positions), length + 1)
            else:
                positions = {i + 1 for i in positions if i < length and fnmatchcase(parts[i], segment)}
            if not positions:
                break
        if length in positions:
            return True
    return False
