"""Контейнеры, в которых лежат расшифрованные скрипты Angry Birds.

После снятия AES-слоя содержимое `options.lua` — это один из трёх вариантов:

* ``7z``   — 7z-архив (внутри файл `options.lua`); так делают большинство
             PC-версий, упакованных 7-Zip (`7za a temp.7z options.lua`);
* ``lzma`` — LZMA-поток с 9-байтовой подписью ``\\x89LZMA\\r\\n\\x1a\\n``
             (старый способ, который понимает движок Fusion);
* ``raw``  — данные как есть (Lua-байткод или исходник).
"""

from __future__ import annotations

import lzma
from dataclasses import dataclass
from typing import Optional

from . import sevenzip

__all__ = [
    "CONTAINER_RAW",
    "CONTAINER_LZMA",
    "CONTAINER_7Z",
    "LZMA_MAGIC",
    "ContainerError",
    "Unpacked",
    "detect",
    "unpack",
    "pack",
    "container_title",
]

CONTAINER_RAW = "raw"
CONTAINER_LZMA = "lzma"
CONTAINER_7Z = "7z"

LZMA_MAGIC = b"\x89LZMA\r\n\x1a\n"


class ContainerError(Exception):
    """Не удалось разобрать контейнер."""


@dataclass
class Unpacked:
    """Результат распаковки контейнера."""

    content: bytes
    container: str
    name: Optional[str] = None       # имя файла внутри архива
    extra_files: int = 0             # сколько ещё файлов было в архиве


def detect(data: bytes) -> str:
    """Определить тип контейнера по «магическим» байтам."""
    if sevenzip.is_7z(data):
        return CONTAINER_7Z
    if data[:9] == LZMA_MAGIC:
        return CONTAINER_LZMA
    return CONTAINER_RAW


def container_title(container: str) -> str:
    return {
        CONTAINER_7Z: "7z-архив",
        CONTAINER_LZMA: "LZMA-поток",
        CONTAINER_RAW: "без архива (как есть)",
    }.get(container, container)


def unpack(data: bytes, container: Optional[str] = None) -> Unpacked:
    """Распаковать контейнер. Для raw просто возвращает данные."""
    kind = container or detect(data)
    if kind == CONTAINER_7Z:
        entries = [e for e in sevenzip.read_archive(data) if e.data or e.name]
        files = [e for e in entries if e.data]
        if not files:
            raise ContainerError("В 7z-архиве нет файлов с данными")
        main = _pick_main_file(files)
        return Unpacked(
            content=main.data,
            container=kind,
            name=main.name,
            extra_files=len(files) - 1,
        )
    if kind == CONTAINER_LZMA:
        if data[:9] != LZMA_MAGIC:
            raise ContainerError("Нет подписи LZMA в начале файла")
        try:
            content = lzma.decompress(data[9:], format=lzma.FORMAT_ALONE)
        except lzma.LZMAError as exc:
            raise ContainerError("Не удалось распаковать LZMA-поток: %s" % exc) from exc
        return Unpacked(content=content, container=kind, name=None)
    if kind == CONTAINER_RAW:
        return Unpacked(content=data, container=kind, name=None)
    raise ContainerError("Неизвестный контейнер: %s" % kind)


def _pick_main_file(files):
    """Выбрать главный файл архива (options.lua и т.п.)."""
    for entry in files:
        name = (entry.name or "").replace("\\", "/").split("/")[-1].lower()
        if name in ("options.lua", "options.json"):
            return entry
    for entry in files:
        name = (entry.name or "").lower()
        if name.endswith(".lua"):
            return entry
    return max(files, key=lambda e: len(e.data))


def pack(content: bytes, container: str, name: Optional[str] = None) -> bytes:
    """Упаковать данные в контейнер нужного типа."""
    if container == CONTAINER_7Z:
        archive_name = name or "options.lua"
        archive_name = archive_name.replace("\\", "/").split("/")[-1]
        return sevenzip.create_archive(archive_name, content)
    if container == CONTAINER_LZMA:
        stream = lzma.compress(content, format=lzma.FORMAT_ALONE)
        return LZMA_MAGIC + stream
    if container == CONTAINER_RAW:
        return content
    raise ContainerError("Неизвестный контейнер: %s" % container)


def guess_inner_name(path: str, fallback: str = "options.lua") -> str:
    """Имя файла для упаковки в архив (обычно — имя самого скрипта)."""
    if not path:
        return fallback
    base = path.replace("\\", "/").split("/")[-1]
    return base or fallback
