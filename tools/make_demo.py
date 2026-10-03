#!/usr/bin/env python3
"""Собирает папку demo/ — тренировочную «установку» игр.

Нужна, чтобы инструмент можно было проверить, не трогая настоящие файлы игры
(и чтобы работал веб-интерфейс прямо из репозитория).

Что получится:

    demo/Angry Birds/data/scripts/options.lua          7z + AES (классика, текст)
    demo/Angry Birds/data/scripts/levels/level1.lua    без архива + AES
    demo/Angry Birds Seasons/data/scripts/options.lua  LZMA + AES (байткод Lua 5.1)

Запуск:  python tools/make_demo.py
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from abluatool import aes, containers, keys, luafmt  # noqa: E402

DEMO_DIR = os.path.join(ROOT, "demo")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

LEVEL_STUB = """-- level1.lua (демо) — просто заготовка уровня
level = {
    index = 1,
    birds = { "red", "chuck", "blue" },
    pigs = 3,
}
return level
""".encode("utf-8")


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    print("  создан %s (%d байт)" % (os.path.relpath(path, ROOT), len(data)))


def build() -> None:
    classic = keys.by_id("classic")
    seasons = keys.by_id("seasons")
    assert classic and seasons

    with open(os.path.join(FIXTURES, "options_source.lua"), "rb") as handle:
        source = handle.read()
    with open(os.path.join(FIXTURES, "options_bytecode.luac"), "rb") as handle:
        bytecode = handle.read()

    print("Классика (7z + текст):")
    packed = containers.pack(source, containers.CONTAINER_7Z, "options.lua")
    _write(
        os.path.join(DEMO_DIR, classic.folders[0], "data", "scripts", "options.lua"),
        aes.encrypt(classic.key, packed),
    )
    _write(
        os.path.join(DEMO_DIR, classic.folders[0], "data", "scripts", "levels", "level1.lua"),
        aes.encrypt(classic.key, LEVEL_STUB),
    )

    print("Seasons (LZMA + байткод Lua 5.1):")
    packed = containers.pack(bytecode, containers.CONTAINER_LZMA)
    _write(
        os.path.join(DEMO_DIR, seasons.folders[0], "data", "scripts", "options.lua"),
        aes.encrypt(seasons.key, packed),
    )

    print("Проверка:")
    for path, game in (
        (os.path.join(DEMO_DIR, classic.folders[0], "data", "scripts", "options.lua"), classic),
        (os.path.join(DEMO_DIR, seasons.folders[0], "data", "scripts", "options.lua"), seasons),
    ):
        data = open(path, "rb").read()
        plain = aes.decrypt(game.key, data)
        unpacked = containers.unpack(plain)
        flags = luafmt.flags_state(unpacked.content)
        print(
            "  %s: контейнер=%s, формат=%s, флаги=%s"
            % (
                os.path.relpath(path, ROOT),
                containers.container_title(unpacked.container),
                luafmt.kind_title(luafmt.detect_kind(unpacked.content)),
                flags,
            )
        )


if __name__ == "__main__":
    build()
