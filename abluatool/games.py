"""Поиск установленных PC-версий Angry Birds.

Программы Rovio на Windows по умолчанию ставятся в
``C:\\Program Files (x86)\\Rovio Entertainment Ltd\\<Игра>``,
поэтому именно там и ищем ``data/scripts/options.lua``.
Дополнительные каталоги можно задать вручную (``--root``).
"""

from __future__ import annotations

import os
import string
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from . import keys
from .keys import Game

__all__ = ["Found", "default_roots", "find_games", "scan_root", "describe"]


@dataclass
class Found:
    """Найденная установка игры."""

    path: str
    options_files: List[str] = field(default_factory=list)
    game: Optional[Game] = None
    source: str = ""

    @property
    def title(self) -> str:
        if self.game:
            return self.game.title
        return os.path.basename(self.path.rstrip("\\/")) or self.path

    def to_text(self) -> str:
        lines = ["%s" % self.title, "  Папка:  %s" % self.path]
        for file in self.options_files:
            lines.append("  Файл:   %s" % file)
        if not self.options_files:
            lines.append("  Файл:   options.lua не найден")
        return "\n".join(lines)


def _program_files_dirs() -> List[str]:
    """Каталоги Program Files (учитываем x86 и локализованные имена)."""
    roots: List[str] = []
    for env in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        value = os.environ.get(env)
        if value and value not in roots:
            roots.append(value)
    if not roots:  # не Windows — просто пустой список
        return []
    out: List[str] = []
    for root in roots:
        for sub in ("Rovio Entertainment Ltd", "Rovio", "Rovio Mobile"):
            candidate = os.path.join(root, sub)
            if os.path.isdir(candidate) and candidate not in out:
                out.append(candidate)
    return out


def default_roots() -> List[str]:
    """Стандартные места, где искать игры."""
    roots: List[str] = []
    roots.extend(_program_files_dirs())
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(os.path.join(local, "Rovio"))
    for drive in string.ascii_uppercase:
        candidate = "%s:\\Games" % drive
        if os.path.isdir(candidate):
            roots.append(candidate)
    # уникализируем, сохраняя порядок
    seen = set()
    result = []
    for root in roots:
        if root.lower() in seen or not os.path.isdir(root):
            continue
        seen.add(root.lower())
        result.append(root)
    return result


def scan_root(root: str, depth: int = 2) -> List[Found]:
    """Просмотреть каталог в поисках установок Angry Birds."""
    root = os.path.abspath(os.path.expanduser(root))
    found: List[Found] = []
    if not os.path.isdir(root):
        return found

    for dirpath, dirnames, _filenames in os.walk(root):
        level = dirpath[len(root):].count(os.sep)
        if level >= depth:
            dirnames[:] = []
        has_options = os.path.exists(os.path.join(dirpath, "data", "scripts", "options.lua"))
        has_data = os.path.isdir(os.path.join(dirpath, "data"))
        if has_options:
            found.append(
                Found(
                    path=dirpath,
                    options_files=[os.path.join(dirpath, "data", "scripts", "options.lua")],
                    game=keys.by_folder_name(dirpath),
                    source=root,
                )
            )
        elif has_data and level < depth:
            # папка игры без options.lua — покажем, но без файлов
            name = os.path.basename(dirpath)
            if keys.by_folder_name(name) or "angry" in name.lower() or "piggies" in name.lower():
                found.append(Found(path=dirpath, options_files=[], game=keys.by_folder_name(name), source=root))
    return found


def find_games(roots: Optional[Sequence[str]] = None) -> List[Found]:
    """Найти установки игр в заданных (или стандартных) каталогах."""
    roots = list(roots) if roots else default_roots()
    result: List[Found] = []
    seen = set()
    for root in roots:
        for found in scan_root(root):
            key = os.path.abspath(found.path).lower()
            if key in seen:
                continue
            seen.add(key)
            result.append(found)
    return result


def describe(found: Found) -> str:
    return found.to_text()
