"""Classify counted Windows paths lexically; never open classification roots."""
import ntpath
import os


LOCATION_ENV = {
    "program_files": ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"),
    "program_data": ("ProgramData",),
    "app_data": ("APPDATA", "LOCALAPPDATA"),
}


def normalized_local_path(value):
    if not isinstance(value, str) or not value or "%" in value:
        return None
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha()
            or not tail.startswith(("/", "\\"))
            or any(char in value[2:] for char in '<>:"|?*')
            or any(ord(char) < 32 for char in value)):
        return None
    return ntpath.normcase(ntpath.normpath(value))


class LocationClassifier:
    def __init__(self, environ=None, *, windows=None):
        environ = os.environ if environ is None else environ
        self.roots = []
        self.known = set()
        windows = os.name == "nt" if windows is None else windows
        if windows:
            for category, variables in LOCATION_ENV.items():
                for variable in variables:
                    path = normalized_local_path(environ.get(variable))
                    if path is not None and ntpath.dirname(path) != path:
                        self.roots.append((path, category))
                        self.known.add(category)

    def classify(self, path):
        path = normalized_local_path(str(path))
        if path is None:
            return "unknown"
        matches = [(len(root), category) for root, category in self.roots
                   if path == root or path.startswith(root + "\\")]
        if matches:
            longest = max(length for length, _ in matches)
            categories = {category for length, category in matches if length == longest}
            return categories.pop() if len(categories) == 1 else "unknown"
        return "other" if len(self.known) == len(LOCATION_ENV) else "unknown"
