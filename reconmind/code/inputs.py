"""
ReconMind code scan inputs.

validate_input(path) checks what a code scan was asked to read and returns a
CodeInput. Files are only listed and measured here. Nothing in this module
imports or runs the analyzed code.

    the path must exist and be a regular file or a folder
    the path itself is resolved once; inside a folder every symbolic link
    must resolve to a place inside that folder, otherwise the whole input is
    refused, so neither ReconMind nor the scanners ever follow a link out
    at most MAX_FILES source files and MAX_BYTES of source in total
    at least one source file in a supported language

Languages come from the file extension only (LANGUAGES). Folders named in
SKIPPED_DIRS are not counted.

read_snippet(root, reported, start, end) reads the lines a tool reported as
plain text, at most MAX_SNIPPET_LINES of them, and only from a file inside
root.
"""

import os
import stat
from collections import Counter, namedtuple

LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".h": "c",
}
MAX_FILES = 5000
MAX_BYTES = 50 * 1024 * 1024
MAX_SNIPPET_LINES = 15
MAX_LINE_CHARS = 300
SKIPPED_DIRS = (".git",)
SHOWN_LINKS = 5

# root: the resolved input path. is_dir: True for a folder. files: source
# files relative to root (a file input lists its own name). languages:
# {language: file count}. total_bytes: size of all source files.
CodeInput = namedtuple("CodeInput", "root is_dir files languages total_bytes")

MISSING = "{p} does not exist."
UNREADABLE = "{p} cannot be read: {e}"
NOT_FILE_OR_FOLDER = "{p} is not a regular file or a folder."
UNSUPPORTED = ("{p} has no source file in a supported language. Supported extensions: "
               "{e}.")
TOO_MANY_FILES = "{p} holds more than {n} source files. Scan a smaller folder."
TOO_MANY_BYTES = "{p} holds more than {mb} MB of source code. Scan a smaller folder."
OUTSIDE_LINKS = ("{p} holds symbolic links that point outside it: {links}. Nothing was "
                 "scanned. Remove those links or scan a folder without them.")


class InputError(ValueError):
    """The input cannot be scanned. The message says why."""


def language_of(path):
    """The language of a file, from its extension, or None."""
    return LANGUAGES.get(os.path.splitext(str(path))[1].lower())


def is_inside(path, root):
    """True when path, with every link resolved, is root itself or inside root."""
    real = os.path.realpath(path)
    return real == root or real.startswith(root.rstrip(os.sep) + os.sep)


def _extensions():
    return ", ".join(sorted(LANGUAGES))


def _single_file(root):
    language = language_of(root)
    if language is None:
        raise InputError(UNSUPPORTED.format(p=root, e=_extensions()))
    size = os.path.getsize(root)
    if size > MAX_BYTES:
        raise InputError(TOO_MANY_BYTES.format(p=root, mb=MAX_BYTES // (1024 * 1024)))
    return CodeInput(root, False, [os.path.basename(root)], {language: 1}, size)


def _folder(root):
    files, counts, total, outside = [], Counter(), 0, []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIPPED_DIRS)
        for name in list(dirnames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                if not is_inside(full, root):
                    outside.append(os.path.relpath(full, root))
                dirnames.remove(name)  # a linked folder is never walked
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                # A link inside the folder points at a file counted on its own.
                if not is_inside(full, root):
                    outside.append(os.path.relpath(full, root))
                continue
            language = language_of(name)
            if language is None:
                continue
            try:
                info = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            files.append(os.path.relpath(full, root))
            counts[language] += 1
            total += info.st_size
            if len(files) > MAX_FILES:
                raise InputError(TOO_MANY_FILES.format(p=root, n=MAX_FILES))
            if total > MAX_BYTES:
                raise InputError(TOO_MANY_BYTES.format(p=root, mb=MAX_BYTES // (1024 * 1024)))
    if outside:
        shown = ", ".join(sorted(outside)[:SHOWN_LINKS])
        if len(outside) > SHOWN_LINKS:
            shown += " and {n} more".format(n=len(outside) - SHOWN_LINKS)
        raise InputError(OUTSIDE_LINKS.format(p=root, links=shown))
    if not files:
        raise InputError(UNSUPPORTED.format(p=root, e=_extensions()))
    return CodeInput(root, True, files, dict(counts), total)


def validate_input(path):
    """Check the input path and return a CodeInput. Raises InputError."""
    text = str(path or "").strip()
    if not text or not os.path.exists(text):
        raise InputError(MISSING.format(p=text or "(empty path)"))
    root = os.path.realpath(text)
    try:
        info = os.stat(root)
    except OSError as exc:
        raise InputError(UNREADABLE.format(p=root, e=exc)) from None
    if stat.S_ISREG(info.st_mode):
        return _single_file(root)
    if stat.S_ISDIR(info.st_mode):
        return _folder(root)
    raise InputError(NOT_FILE_OR_FOLDER.format(p=root))


def resolve_reported(root, reported):
    """
    (real path, display path) for a file path a tool reported. The display
    path is relative to a folder input, or the file's name for a file input.
    A path outside root gives (None, the path as reported).
    """
    if not reported:
        return None, ""
    real = os.path.realpath(os.path.abspath(str(reported)))
    if not is_inside(real, root):
        return None, str(reported)
    if os.path.isdir(root):
        return real, os.path.relpath(real, root)
    return real, os.path.basename(real)


def read_snippet(root, reported, start, end=None):
    """
    Lines start to end (1 based, inclusive) of a reported file, as text.
    At most MAX_SNIPPET_LINES lines of at most MAX_LINE_CHARS characters.
    "" when the file is outside root, cannot be read or the lines are bad.
    """
    real, _ = resolve_reported(root, reported)
    try:
        start = int(start)
        end = int(end) if end else start
    except (TypeError, ValueError):
        return ""
    if real is None or start < 1:
        return ""
    end = max(start, min(end, start + MAX_SNIPPET_LINES - 1))
    lines = []
    try:
        with open(real, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, start=1):
                if number > end:
                    break
                if number >= start:
                    lines.append(line.rstrip("\r\n")[:MAX_LINE_CHARS])
    except OSError:
        return ""
    return "\n".join(lines)
