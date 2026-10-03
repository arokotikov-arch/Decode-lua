"""Высокоуровневые операции: расшифровка, правка, упаковка, шифрование.

Здесь собрана вся последовательность из гайда:

1. читаем ``data/scripts/options.lua`` из папки игры;
2. подбираем ключ (или берём указанный) и снимаем AES-256-CBC;
3. распаковываем контейнер (7z -> LZMA -> как есть);
4. выключаем ``g_registrationEnabled`` и ``g_updateCheckEnabled``;
5. упаковываем обратно в тот же контейнер и шифруем тем же ключом;
6. проверяем результат (расшифровываем копию и сверяем флаги);
7. пишем файл, сохраняя резервную копию ``*.ablua.bak``.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import aes, containers, keys, luafmt, sevenzip
from .containers import CONTAINER_RAW, LZMA_MAGIC
from .keys import Game

__all__ = [
    "EngineError",
    "KeyNotFound",
    "Analysis",
    "Report",
    "backup_path",
    "analyze",
    "activate",
    "decrypt_file",
    "encrypt_file",
    "restore",
    "has_backup",
    "payload_score",
]

BACKUP_SUFFIX = ".ablua.bak"


class EngineError(Exception):
    """Общая ошибка обработки файла."""


class KeyNotFound(EngineError):
    """Ни один известный ключ не подошёл."""


# --------------------------------------------------------------------------
# Вспомогательное
# --------------------------------------------------------------------------

def backup_path(path: str) -> str:
    return path + BACKUP_SUFFIX


def has_backup(path: str) -> bool:
    return os.path.exists(backup_path(path))


def payload_score(data: bytes) -> int:
    """Насколько правдоподобно, что это содержимое скрипта Angry Birds.

    Нужен, чтобы отличить верный ключ от случайного (неверный ключ может
    дать корректное дополнение PKCS#7 с вероятностью ~1/256).
    """
    if not data:
        return -1
    if sevenzip.is_7z(data) or data[:9] == LZMA_MAGIC:
        return 100
    kind = luafmt.detect_kind(data)
    if kind in (luafmt.KIND_LUA_BYTECODE, luafmt.KIND_LUA_TEXT, luafmt.KIND_JSON):
        return 80
    return -1


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ablua-tmp-")
    except OSError as exc:
        raise EngineError(_permission_hint(path, exc)) from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        shutil.copymode(path, tmp) if os.path.exists(path) else None
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise EngineError(_permission_hint(path, exc)) from exc


def _permission_hint(path: str, exc: OSError) -> str:
    if isinstance(exc, PermissionError) or getattr(exc, "errno", None) in (13, 1):
        return (
            "Нет прав на запись в %s.\n"
            "Программы Rovio лежат в Program Files, поэтому запустите инструмент "
            "от имени администратора (правый клик -> «Запуск от имени администратора»)."
            % path
        )
    return "Не удалось записать %s: %s" % (path, exc)


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError as exc:
        raise EngineError("Файл не найден: %s" % path) from exc
    except OSError as exc:
        raise EngineError("Не удалось прочитать %s: %s" % (path, exc)) from exc


# --------------------------------------------------------------------------
# Работа с ключами
# --------------------------------------------------------------------------

def _candidate_keys(
    path: str, game: Optional[Game] = None, key: Optional[bytes] = None
) -> List[Tuple[Optional[Game], bytes]]:
    if key is not None:
        return [(keys.game_with_key(game, key), key)]
    if game is not None and game.key:
        return [(game, game.key)]
    # сначала игра, угаданная по пути установки, затем все остальные
    out: List[Tuple[Optional[Game], bytes]] = []
    seen = set()
    for candidate in keys.games_for_path(path):
        if candidate.key in seen:
            continue
        seen.add(candidate.key)
        out.append((candidate, candidate.key))
    return out


def detect_key(
    data: bytes,
    path: str = "",
    game: Optional[Game] = None,
    key: Optional[bytes] = None,
) -> Tuple[Optional[Game], bytes, bytes, int]:
    """Подобрать ключ шифрования.

    Возвращает (игра, ключ, расшифрованные данные, оценка правдоподобности).
    """
    candidates = _candidate_keys(path, game, key)
    best = None
    attempts: List[str] = []
    for candidate_game, candidate_key in candidates:
        try:
            plain = aes.decrypt(candidate_key, data)
        except ValueError as exc:
            attempts.append("%s: %s" % (candidate_game.title if candidate_game else "?", exc))
            continue
        score = payload_score(plain)
        if score > 0 and (best is None or score > best[3]):
            best = (candidate_game, candidate_key, plain, score)
            if score >= 100:
                break
    if best is None:
        raise KeyNotFound(
            "Не удалось расшифровать файл ни одним известным ключом.\n"
            "Проверьте, что это действительно data/scripts/options.lua из PC-версии "
            "Angry Birds (а не файл сохранения), либо укажите ключ вручную "
            "параметром --key (32 символа или 64 hex-цифры)."
        )
    return best


# --------------------------------------------------------------------------
# Описание файла
# --------------------------------------------------------------------------

def _plaintext_and_key(
    data: bytes,
    path: str,
    game: Optional[Game],
    key: Optional[bytes],
) -> Tuple[bytes, Optional[Game], Optional[bytes]]:
    """Разобраться, зашифрован ли файл, и вернуть (данные, игра, ключ).

    Если файл уже расшифрован (например, его подготовили вручную), ключ
    может быть не нужен — тогда третий элемент None.
    """
    if payload_score(data) > 0:
        # данные выглядят как готовое содержимое, а не как шифртекст
        if key is None and game is None:
            return data, keys.by_folder_name(path), None
    found_game, found_key, plain, _score = detect_key(data, path, game, key)
    return plain, found_game, found_key


@dataclass
class Analysis:
    """Что удалось выяснить про файл."""

    path: str
    size: int
    game: Optional[Game] = None
    key: Optional[bytes] = None
    container: str = CONTAINER_RAW
    inner_name: Optional[str] = None
    inner_kind: str = luafmt.KIND_BINARY
    inner_size: int = 0
    extra_files: int = 0
    flags: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_text(self) -> str:
        lines = ["Файл:            %s" % self.path,
                 "Размер:          %d байт" % self.size]
        if self.error:
            lines.append("Ошибка:          %s" % self.error)
            return "\n".join(lines)
        lines += [
            "Игра:            %s" % (self.game.title if self.game else "не определена"),
            "Ключ:            %s" % (self.key.decode("ascii", "replace") if self.key else "-"),
            "Контейнер:       %s" % containers.container_title(self.container),
            "Внутри:          %s (%.1f КБ)" % (
                luafmt.kind_title(self.inner_kind), self.inner_size / 1024.0),
        ]
        if self.inner_name:
            lines.append("Имя в архиве:    %s" % self.inner_name)
        if self.extra_files:
            lines.append("Файлов в архиве: %d (взят основной)" % (self.extra_files + 1))
        if self.flags:
            for name, value in sorted(self.flags.items()):
                lines.append("Флаг %-24s %s" % (name, "включён (true)" if value == "true" else "выключен (false)"))
        else:
            lines.append("Флаги:           не найдены в этом файле")
        for note in self.notes:
            lines.append("Примечание:      %s" % note)
        return "\n".join(lines)


def analyze(
    path: str,
    game: Optional[Game] = None,
    key: Optional[bytes] = None,
    container: Optional[str] = None,
) -> Analysis:
    """Разобрать файл: определить игру, контейнер, формат и текущие флаги."""
    data = _read(path)
    info = Analysis(path=path, size=len(data))
    try:
        plain, found_game, found_key = _plaintext_and_key(data, path, game, key)
        info.game, info.key = found_game, found_key
        if found_key is None:
            info.notes.append("файл не зашифрован (или уже расшифрован)")
        unpacked = containers.unpack(plain, container)
        info.container = unpacked.container
        info.inner_name = unpacked.name
        info.extra_files = unpacked.extra_files
        info.inner_size = len(unpacked.content)
        info.inner_kind = luafmt.detect_kind(unpacked.content)
        info.flags = luafmt.flags_state(unpacked.content)
        if info.inner_kind == luafmt.KIND_LUAJIT:
            info.notes.append("байткод LuaJIT: правка флагов не поддерживается автоматически")
    except (EngineError, containers.ContainerError, luafmt.BytecodeError) as exc:
        info.error = str(exc)
    return info


# --------------------------------------------------------------------------
# Отчёты об операциях
# --------------------------------------------------------------------------

@dataclass
class Report:
    """Результат операции над файлом."""

    action: str
    path: str
    out_path: Optional[str] = None
    backup: Optional[str] = None
    game: Optional[Game] = None
    key: Optional[bytes] = None
    container: str = CONTAINER_RAW
    inner_kind: str = luafmt.KIND_BINARY
    changes: List[luafmt.Change] = field(default_factory=list)
    flags_before: Dict[str, str] = field(default_factory=dict)
    flags_after: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    written: bool = False
    verified: bool = False
    dry_run: bool = False
    show_content: bool = True

    @property
    def changed(self) -> bool:
        """Были ли реальные правки содержимого."""
        return bool(self.changes)

    def to_text(self) -> str:
        head = {
            "activate": "Активация",
            "decrypt": "Расшифровка",
            "encrypt": "Шифрование",
            "restore": "Восстановление",
            "info": "Анализ",
        }.get(self.action, self.action)
        lines = ["=== %s ===" % head, "Файл:       %s" % self.path]
        if self.game:
            lines.append("Игра:       %s" % self.game.title)
        if self.key:
            lines.append("Ключ:       %s" % self.key.decode("ascii", "replace"))
        if self.show_content:
            lines.append("Контейнер:  %s" % containers.container_title(self.container))
            lines.append("Внутри:     %s" % luafmt.kind_title(self.inner_kind))
        if self.flags_before:
            lines.append("Флаги до:   %s" % _flags_text(self.flags_before))
        if self.flags_after:
            lines.append("Флаги после:%s" % _flags_text(self.flags_after))
        for change in self.changes:
            lines.append("  * %s" % change)
        if self.backup:
            lines.append("Резервная копия: %s" % self.backup)
        if self.out_path:
            lines.append("Результат:  %s" % self.out_path)
        if self.dry_run:
            lines.append("Режим:      проверка без записи (--dry-run)")
        elif self.written:
            lines.append("Записано:   да")
        if self.verified:
            lines.append("Проверка:   результат расшифрован и сверен — всё в порядке")
        for note in self.notes:
            lines.append("Примечание: %s" % note)
        return "\n".join(lines)


def _flags_text(flags: Dict[str, str]) -> str:
    return ", ".join("%s=%s" % (name, value) for name, value in sorted(flags.items())) or "нет данных"


# --------------------------------------------------------------------------
# Основные операции
# --------------------------------------------------------------------------

def activate(
    path: str,
    game: Optional[Game] = None,
    key: Optional[bytes] = None,
    backup: bool = True,
    dry_run: bool = False,
    verify: bool = True,
    container: Optional[str] = None,
    inner_name: Optional[str] = None,
) -> Report:
    """Главная операция: выключить регистрацию и проверку обновлений.

    Файл на диске заменяется на активированную версию (с резервной копией).
    """
    data = _read(path)
    report = Report(action="activate", path=path, dry_run=dry_run)
    plain = data
    already_plain = payload_score(data) > 0
    if already_plain:
        found_game = game or keys.by_folder_name(path)
        found_key = key or (found_game.key if found_game else None)
        if found_key is None:
            raise EngineError(
                "Файл %s не зашифрован (внутри уже готовое содержимое).\n"
                "Укажите игру или ключ, чтобы зашифровать его как надо: "
                "--game classic (или --key <32 символа>)." % path
            )
        report.notes.append(
            "файл был не зашифрован — результат будет зашифрован выбранным ключом"
        )
    else:
        found_game, found_key, plain, _score = detect_key(data, path, game, key)
    report.game, report.key = found_game, found_key

    unpacked = containers.unpack(plain, container)
    report.container = unpacked.container
    report.inner_kind = luafmt.detect_kind(unpacked.content)
    report.flags_before = luafmt.flags_state(unpacked.content)

    patch = luafmt.patch(unpacked.content)
    report.changes = patch.changes
    report.flags_after = luafmt.flags_state(patch.data)
    if patch.already_off:
        report.notes.append(
            "уже выключены: %s" % ", ".join(sorted(set(patch.already_off)))
        )
    if patch.missing:
        report.notes.append(
            "не найдены в файле: %s" % ", ".join(patch.missing)
        )

    if not patch.changed:
        report.notes.append("изменения не требуются — файл уже активирован")
        report.notes.append("файл не изменялся, резервная копия не нужна")
        return report

    name = inner_name or unpacked.name or containers.guess_inner_name(path)
    repacked = containers.pack(patch.data, unpacked.container, name)
    encrypted = aes.encrypt(found_key, repacked)

    if verify:
        check_plain = aes.decrypt(found_key, encrypted)
        check = containers.unpack(check_plain, unpacked.container)
        state = luafmt.flags_state(check.content)
        report.verified = all(state.get(f) == "false" for f in luafmt.FLAG_NAMES) and (
            check.content == patch.data
        )
        if not report.verified:
            raise EngineError("Проверка не пройдена: результат не совпал с ожидаемым")

    if dry_run:
        return report

    if backup and os.path.exists(path):
        shutil.copy2(path, backup_path(path))
        report.backup = backup_path(path)
    _atomic_write(path, encrypted)
    report.written = True
    return report


def decrypt_file(
    path: str,
    out_path: Optional[str] = None,
    game: Optional[Game] = None,
    key: Optional[bytes] = None,
    unpack: bool = True,
) -> Report:
    """Расшифровать файл (и при желании распаковать контейнер)."""
    data = _read(path)
    report = Report(action="decrypt", path=path)
    found_game, found_key, plain, _score = detect_key(data, path, game, key)
    report.game, report.key = found_game, found_key
    report.container = containers.detect(plain)
    report.inner_kind = luafmt.detect_kind(plain)
    result = plain
    if unpack:
        unpacked = containers.unpack(plain)
        result = unpacked.content
        report.container = unpacked.container
        report.inner_kind = luafmt.detect_kind(result)
        report.flags_before = luafmt.flags_state(result)
    out_path = out_path or (path + (".lua" if unpack else ".dec"))
    _atomic_write(out_path, result)
    report.out_path = out_path
    report.written = True
    return report


def encrypt_file(
    path: str,
    out_path: str,
    game: Optional[Game] = None,
    key: Optional[bytes] = None,
    container: str = CONTAINER_RAW,
    inner_name: Optional[str] = None,
) -> Report:
    """Зашифровать подготовленный файл (Lua/JSON) в формат игры."""
    data = _read(path)
    if key is None:
        if game is None:
            raise EngineError("Нужно указать ключ (--key) или игру (--game)")
        key = game.key
    report = Report(action="encrypt", path=path, out_path=out_path, key=key, game=game)
    content = data
    if container != CONTAINER_RAW:
        content = containers.pack(data, container, inner_name or containers.guess_inner_name(path))
    report.container = container
    # сообщаем формат исходного файла, а не упакованного
    report.inner_kind = luafmt.detect_kind(data)
    encrypted = aes.encrypt(key, content)
    _atomic_write(out_path, encrypted)
    report.written = True
    return report


def restore(path: str) -> Report:
    """Вернуть исходный файл из резервной копии."""
    report = Report(action="restore", path=path, show_content=False)
    backup = backup_path(path)
    if not os.path.exists(backup):
        raise EngineError(
            "Резервная копия не найдена: %s\nВосстанавливать нечего." % backup
        )
    data = _read(backup)
    _atomic_write(path, data)
    report.backup = backup
    report.written = True
    report.notes.append("исходный файл восстановлен из резервной копии")
    return report


def find_options_files(root: str) -> List[str]:
    """Найти все data/scripts/options.lua в каталоге игры."""
    root = os.path.abspath(root)
    found: List[str] = []
    candidate = os.path.join(root, "data", "scripts", "options.lua")
    if os.path.exists(candidate):
        found.append(candidate)
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath).lower() == "scripts":
            for name in filenames:
                if name.lower() in ("options.lua", "options.json"):
                    full = os.path.join(dirpath, name)
                    if full not in found:
                        found.append(full)
        # не проваливаемся слишком глубоко
        if dirpath.count(os.sep) - root.count(os.sep) > 4:
            dirnames[:] = []
    return found
