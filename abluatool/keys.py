"""Ключи шифрования PC-версий Angry Birds.

Ключ — 32 ASCII-символа (AES-256), зашифрованный файл лежит в
`data/scripts/options.lua`. Значения взяты из открытого проекта
AB360 LUA Manager (github.com/AB360-org/LUAManager), на который ссылается
гайд Angry Birds Wiki «How to activate PC games (2024)».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "Game",
    "GAMES",
    "CLASSIC_KEY",
    "by_id",
    "by_folder_name",
    "all_keys",
    "games_for_path",
]

#: Ключ классической Angry Birds и Angry Birds Rio (совпадают)
CLASSIC_KEY = b"USCaPQpA4TSNVxMI1v9SK9UC0yZuAnb2"


@dataclass(frozen=True)
class Game:
    """Описание игры: название, ключ и типичные имена папок установки."""

    id: str
    title: str
    key: bytes
    folders: Tuple[str, ...] = field(default_factory=tuple)
    note: str = ""

    @property
    def key_hex(self) -> str:
        return self.key.hex()

    @property
    def key_ascii(self) -> str:
        return self.key.decode("ascii", "replace")


GAMES: Tuple[Game, ...] = (
    Game(
        id="classic",
        title="Angry Birds (классика)",
        key=CLASSIC_KEY,
        folders=("Angry Birds", "Angry Birds Classic"),
        note="C:\\Program Files (x86)\\Rovio Entertainment Ltd\\Angry Birds",
    ),
    Game(
        id="seasons",
        title="Angry Birds Seasons",
        key=b"zePhest5faQuX2S2Apre@4reChAtEvUt",
        folders=("Angry Birds Seasons",),
    ),
    Game(
        id="rio",
        title="Angry Birds Rio",
        key=CLASSIC_KEY,
        folders=("Angry Birds Rio",),
        note="ключ совпадает с классической Angry Birds",
    ),
    Game(
        id="space",
        title="Angry Birds Space",
        key=b"RmgdZ0JenLFgWwkYvCL2lSahFbEhFec4",
        folders=("Angry Birds Space",),
    ),
    Game(
        id="starwars",
        title="Angry Birds Star Wars",
        key=b"An8t3mn8U6spiQ0zHHr3a1loDrRa3mtE",
        folders=("Angry Birds Star Wars",),
    ),
    Game(
        id="starwars2",
        title="Angry Birds Star Wars II",
        key=b"B0pm3TAlzkN9ghzoe2NizEllPdN0hQni",
        folders=("Angry Birds Star Wars II",),
    ),
    Game(
        id="friends",
        title="Angry Birds Friends",
        key=b"EJRbcWh81YG4YzjfLAPMssAnnzxQaDn1",
        folders=("Angry Birds Friends",),
    ),
)

_BY_ID: Dict[str, Game] = {g.id: g for g in GAMES}


def by_id(game_id: str) -> Optional[Game]:
    """Найти игру по идентификатору (classic, seasons, rio, ...)."""
    return _BY_ID.get((game_id or "").strip().lower())


def by_folder_name(path: str) -> Optional[Game]:
    """Угадать игру по пути установки.

    Из совпадений выбирается самое длинное название папки, иначе
    «Angry Birds» перебивало бы «Angry Birds Seasons».
    """
    text = (path or "").replace("/", "\\").lower()
    best: Optional[Game] = None
    best_len = -1
    for game in GAMES:
        for folder in game.folders:
            needle = folder.lower()
            if needle in text and len(needle) > best_len:
                best = game
                best_len = len(needle)
    return best


def games_for_path(path: str) -> List[Game]:
    """Список игр, которые стоит проверить для данного пути (сначала угаданная)."""
    guess = by_folder_name(path)
    others = [g for g in GAMES if g is not guess]
    return ([guess] if guess else []) + others


def all_keys() -> List[Tuple[Game, bytes]]:
    """Все известные пары (игра, ключ) без дублей ключей."""
    seen = set()
    out: List[Tuple[Game, bytes]] = []
    for game in GAMES:
        if game.key in seen:
            continue
        seen.add(game.key)
        out.append((game, game.key))
    return out


def key_from_text(text: str) -> bytes:
    """Преобразовать ключ из аргумента командной строки (hex или текст)."""
    text = (text or "").strip()
    if len(text) == 64:
        try:
            raw = bytes.fromhex(text)
            if len(raw) == 32:
                return raw
        except ValueError:
            pass
    raw = text.encode("ascii", "replace")
    if len(raw) != 32:
        raise ValueError(
            "Ключ должен быть 32 символа ASCII или 64 hex-символа (получено %d)" % len(raw)
        )
    return raw


def game_with_key(game: Optional[Game], key: Optional[bytes]) -> Optional[Game]:
    """Собрать «виртуальную» игру для произвольного ключа."""
    if key is None:
        return game
    if game is not None and game.key == key:
        return game
    return Game(id="custom", title="Свой ключ", key=key)
