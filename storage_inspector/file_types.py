"""Classify the last filename suffix using the bundled, validated mapping."""
import json
from pathlib import Path
import re


MAPPING_PATH = Path(__file__).with_name("file_types.json")
CATEGORIES = frozenset(("image", "video", "audio", "document", "code", "archive", "other"))


def unique_categories(pairs):
    mapping = {}
    for category, extensions in pairs:
        if category in mapping:
            raise ValueError(f"文件类型映射重复类别：{category}")
        mapping[category] = extensions
    return mapping


def load_file_types():
    try:
        mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"),
                             object_pairs_hook=unique_categories)
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"无法读取文件类型映射：{error}") from error
    if not isinstance(mapping, dict) or set(mapping) != CATEGORIES:
        raise ValueError("文件类型映射必须包含七个固定类别")
    lookup = {}
    for category, extensions in mapping.items():
        if not isinstance(extensions, list) or (category == "other" and extensions):
            raise ValueError(f"文件类型映射类别格式错误：{category}")
        for extension in extensions:
            if (not isinstance(extension, str) or re.fullmatch(r"\.[a-z0-9]+", extension) is None
                    or extension in lookup):
                raise ValueError(f"文件类型映射后缀无效或重复：{extension}")
            lookup[extension] = category
    return lookup
