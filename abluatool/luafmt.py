"""Правка Lua-скриптов Angry Birds: флаги активации в исходнике и в байткоде.

Гайд предлагает: расшифровать options.lua, «декодировать» байткод,
найти строки `gamelua.g_registrationEnabled` и `gamelua.g_updateCheckEnabled`
и заменить `true` на `false`. Здесь это делается автоматически, причём
работают оба варианта файла:

* **исходный текст** — замена по регулярному выражению;
* **байткод Lua 5.1** — правка самой инструкции `LOADBOOL` в чанке
  (декодер байткода не нужен, файл остаётся валидным).

Если в файле лежит LuaJIT-байткод (`\\x1bLJ`) или иной экзотический формат,
возвращается понятная ошибка с подсказкой, что делать.
"""

from __future__ import annotations

import os
import re
import struct
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

__all__ = [
    "KIND_LUA_TEXT",
    "KIND_LUA_BYTECODE",
    "KIND_LUAJIT",
    "KIND_JSON",
    "KIND_BINARY",
    "Change",
    "PatchResult",
    "detect_kind",
    "kind_title",
    "patch",
    "flags_state",
    "decompile",
    "find_unluac_jar",
    "BytecodeError",
]

KIND_LUA_TEXT = "lua-text"
KIND_LUA_BYTECODE = "lua-bytecode"
KIND_LUAJIT = "luajit-bytecode"
KIND_JSON = "json"
KIND_BINARY = "binary"

LUA_SIGNATURE = b"\x1bLua"
LUAJIT_SIGNATURE = b"\x1bLJ"

#: Имена флагов, которые нужно выключить
FLAG_NAMES: Tuple[str, ...] = ("g_registrationEnabled", "g_updateCheckEnabled")

_LUA_SIGNATURE_RE = re.compile(rb"^\x1bLua")
_LUAJIT_SIGNATURE_RE = re.compile(rb"^\x1bLJ")

# --- Lua 5.1: коды операций -------------------------------------------------
OP_LOADBOOL = 2
OP_GETGLOBAL = 5
OP_GETTABLE = 6
OP_SETGLOBAL = 7
OP_SETTABLE = 9

LFIELDS_PER_FLUSH = 50     # не используется, оставлено для совместимости

BITRK = 1 << 8
MAXINDEXRK = BITRK - 1


class BytecodeError(Exception):
    """Байткод Lua не удалось разобрать."""


@dataclass
class Change:
    """Одно найденное и исправленное место."""

    name: str
    old: str
    new: str
    where: str = ""

    def __str__(self) -> str:
        tail = (" (%s)" % self.where) if self.where else ""
        return "%s: %s -> %s%s" % (self.name, self.old, self.new, tail)


@dataclass
class PatchResult:
    """Результат правки файла."""

    data: bytes
    kind: str
    changes: List[Change] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    already_off: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.changes)


# --------------------------------------------------------------------------
# Определение формата
# --------------------------------------------------------------------------

def detect_kind(data: bytes) -> str:
    """Определить, что за данные: текст Lua, байткод, JSON или что-то иное."""
    if not data:
        return KIND_BINARY
    if data.startswith(LUA_SIGNATURE):
        return KIND_LUA_BYTECODE
    if data.startswith(LUAJIT_SIGNATURE):
        return KIND_LUAJIT
    text = decode_text(data[:4096])
    if text is None:
        return KIND_BINARY
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return KIND_JSON
    if re.search(r"\b(function|local|end|return|if|then)\b", text) or "=" in text:
        return KIND_LUA_TEXT
    return KIND_BINARY


def decode_text_with_encoding(data: bytes) -> Optional[Tuple[str, str]]:
    """Прочитать данные как текст и вернуть (текст, кодировка).

    Шифртекст здесь отсекается: он либо не декодируется, либо содержит
    слишком много управляющих символов.
    """
    if not data or b"\x00" in data:
        return None
    for encoding in ("utf-8", "cp1251"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        bad = sum(1 for char in text if char < " " and char not in "\t\r\n")
        if len(text) and bad / len(text) <= 0.02:
            return text, encoding
    return None


def decode_text(data: bytes) -> Optional[str]:
    """Прочитать данные как текст (UTF-8 или cp1251); None, если это не текст."""
    decoded = decode_text_with_encoding(data)
    return decoded[0] if decoded else None


def kind_title(kind: str) -> str:
    return {
        KIND_LUA_TEXT: "исходный текст Lua",
        KIND_LUA_BYTECODE: "байткод Lua 5.1",
        KIND_LUAJIT: "байткод LuaJIT",
        KIND_JSON: "JSON",
        KIND_BINARY: "двоичные данные",
    }.get(kind, kind)


def _looks_textual(data: bytes, threshold: float = 0.90) -> bool:
    """True, если данные похожи на текст (используется только в отчётах)."""
    return decode_text(data) is not None


# --------------------------------------------------------------------------
# Правка текстовых файлов (Lua-исходник, JSON)
# --------------------------------------------------------------------------

_LUA_PATTERN = re.compile(
    rb"(?P<prefix>[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    rb"(?P<name>g_registrationEnabled|g_updateCheckEnabled|registrationEnabled|updateCheckEnabled)"
    rb"(?P<space>\s*=\s*)"
    rb"(?P<value>true|false)",
    re.IGNORECASE,
)

_JSON_PATTERN = re.compile(
    rb'"(?P<name>g_registrationEnabled|g_updateCheckEnabled|registrationEnabled|updateCheckEnabled)"'
    rb'(?P<space>\s*:\s*)'
    rb"(?P<value>true|false)",
    re.IGNORECASE,
)


def _patch_text(data: bytes) -> PatchResult:
    """Замена true -> false в исходнике Lua (кодировка файла сохраняется)."""
    decoded = decode_text_with_encoding(data)
    text, encoding = decoded if decoded else (data.decode("utf-8", "replace"), "utf-8")
    changes: List[Change] = []
    already: List[str] = []
    counter = {"n": 0}

    def repl(match: "re.Match") -> bytes:
        name = match.group("name").decode("ascii", "replace")
        value = match.group("value").decode("ascii").lower()
        counter["n"] += 1
        line = text[: match.start()].count("\n") + 1
        where = "строка %d" % line
        if _in_line_comment(data, match.start()) or _in_string_literal(data, match.start()):
            # в комментариях и строках ничего не меняем — это просто текст
            return match.group(0)
        if value == "false":
            already.append(name)
            return match.group(0)
        changes.append(Change(name=name, old="true", new="false", where=where))
        return match.group(0)[: match.start("value") - match.start()] + b"false"

    new_text = _LUA_PATTERN.sub(repl, text.encode(encoding)).decode(encoding, "replace")
    new_data = new_text.encode(encoding)
    result = PatchResult(data=new_data, kind=KIND_LUA_TEXT, changes=changes, already_off=already)
    if not changes and not already:
        result.missing = list(FLAG_NAMES)
    return result


def _in_line_comment(data: bytes, position: int) -> bool:
    """True, если позиция попадает в однострочный комментарий Lua (`--`)."""
    line_start = data.rfind(b"\n", 0, position) + 1
    line = data[line_start:position]
    comment = line.find(b"--")
    if comment < 0:
        return False
    before = line[:comment]
    return before.count(b'"') % 2 == 0 and before.count(b"'") % 2 == 0


def _in_string_literal(data: bytes, position: int) -> bool:
    """True, если позиция попадает внутрь строкового литерала на этой строке."""
    line_start = data.rfind(b"\n", 0, position) + 1
    line = data[line_start:position]
    return line.count(b'"') % 2 == 1 or line.count(b"'") % 2 == 1


def _patch_json(data: bytes) -> PatchResult:
    """Замена true -> false в JSON-файле."""
    changes: List[Change] = []
    already: List[str] = []
    text = data.decode("utf-8", "replace")

    def repl(match: "re.Match") -> bytes:
        name = match.group("name").decode("ascii", "replace")
        value = match.group("value").decode("ascii").lower()
        if value == "false":
            already.append(name)
            return match.group(0)
        line = text[: match.start()].count("\n") + 1
        changes.append(Change(name=name, old="true", new="false", where="строка %d" % line))
        return match.group(0)[: match.start("value") - match.start()] + b"false"

    new_data = _JSON_PATTERN.sub(repl, data)
    result = PatchResult(data=new_data, kind=KIND_JSON, changes=changes, already_off=already)
    if not changes and not already:
        result.missing = list(FLAG_NAMES)
    return result


def flags_state(data: bytes) -> dict:
    """Текущие значения флагов (для отчёта «до/после»)."""
    kind = detect_kind(data)
    state = {}
    pattern = _JSON_PATTERN if kind == KIND_JSON else _LUA_PATTERN
    for match in pattern.finditer(data):
        name = match.group("name").decode("ascii", "replace")
        value = match.group("value").decode("ascii").lower()
        state[name] = value
    if kind == KIND_LUA_BYTECODE:
        state = _bytecode_flags_state(data)
    return state


# --------------------------------------------------------------------------
# Разбор байткода Lua 5.1
# --------------------------------------------------------------------------

@dataclass
class _Proto:
    source: Optional[str]
    line_defined: int
    line_last: int
    code_offset: int          # смещение массива инструкций в файле
    code_count: int
    constants: List[Tuple[int, object]]
    const_offsets: List[int]
    children: List["_Proto"]
    consts_count_offset: int = 0   # где лежит счётчик констант (int)
    consts_end: int = 0            # сразу после последней константы
    consts_start: int = 0          # сразу после счётчика констант
    name: str = "главный блок"

    def constant_type(self, index: int) -> int:
        if 0 <= index < len(self.constants):
            return self.constants[index][0]
        return -1

    def constant_value(self, index: int):
        if 0 <= index < len(self.constants):
            return self.constants[index][1]
        return None


class _Reader:
    """Чтение значений из чанка байткода Lua."""

    def __init__(self, data: bytes, endian: str, size_t: int, int_size: int, num_size: int):
        self.data = data
        self.pos = 0
        self.endian = endian
        self.size_t = size_t
        self.int_size = int_size
        self.num_size = num_size

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise BytecodeError("Неожиданный конец байткода")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def byte(self) -> int:
        return self.bytes(1)[0]

    def integer(self) -> int:
        raw = self.bytes(self.int_size)
        return int.from_bytes(raw, self.endian, signed=True)

    def size(self) -> int:
        raw = self.bytes(self.size_t)
        return int.from_bytes(raw, self.endian, signed=False)

    def string(self) -> Optional[bytes]:
        size = self.size()
        if size == 0:
            return None
        raw = self.bytes(size)
        return raw.rstrip(b"\x00")

    def number(self) -> float:
        raw = self.bytes(self.num_size)
        return float(struct.unpack(("<" if self.endian == "little" else ">") + "d", raw)[0])


def _parse_chunk(data: bytes) -> Tuple[_Reader, _Proto]:
    """Разобрать чанк байткода и вернуть первый (главный) прототип."""
    if not data.startswith(LUA_SIGNATURE):
        raise BytecodeError("Это не байткод Lua")
    if data.startswith(LUAJIT_SIGNATURE):
        raise BytecodeError("Это байткод LuaJIT — он не поддерживается")
    if len(data) < 12:
        raise BytecodeError("Слишком короткий заголовок байткода")
    version = data[4]
    fmt = data[5]
    endian_byte = data[6]
    int_size = data[7]
    size_t = data[8]
    instr_size = data[9]
    num_size = data[10]
    integral = data[11]  # 0 = числа с плавающей точкой, 1 = целые

    if version != 0x51:
        raise BytecodeError("Поддерживается только Lua 5.1 (версия чанка 0x%02X)" % version)
    if fmt != 0:
        raise BytecodeError("Неизвестный формат чанка (0x%02X)" % fmt)
    if endian_byte not in (0, 1):
        raise BytecodeError("Неизвестный порядок байт в чанке")
    if instr_size != 4:
        raise BytecodeError("Необычный размер инструкции: %d" % instr_size)
    if size_t not in (4, 8):
        raise BytecodeError("Необычный размер size_t: %d" % size_t)
    if integral not in (0, 1):
        raise BytecodeError("Неизвестный формат чисел в чанке")

    reader = _Reader(
        data,
        endian="little" if endian_byte == 1 else "big",
        size_t=size_t,
        int_size=int_size,
        num_size=num_size,
    )
    reader.pos = 12
    proto = _read_proto(reader)
    return reader, proto


def _read_proto(reader: _Reader) -> _Proto:
    source = reader.string()
    line_defined = reader.integer()
    line_last = reader.integer()
    reader.byte()   # nups
    reader.byte()   # numparams
    reader.byte()   # is_vararg
    reader.byte()   # maxstacksize

    code_count = reader.integer()
    code_offset = reader.pos
    reader.bytes(code_count * 4)

    consts_count_offset = reader.pos
    const_count = reader.integer()
    consts_start = reader.pos
    constants: List[Tuple[int, object]] = []
    const_offsets: List[int] = []
    for _ in range(const_count):
        const_offsets.append(reader.pos)
        const_type = reader.byte()
        if const_type == 0:
            constants.append((0, None))
        elif const_type == 1:
            constants.append((1, bool(reader.byte())))
        elif const_type == 3:
            constants.append((3, reader.number()))
        elif const_type == 4:
            raw = reader.string()
            constants.append((4, (raw or b"").decode("utf-8", "replace")))
        else:
            raise BytecodeError("Неизвестный тип константы: %d" % const_type)
    consts_end = reader.pos

    proto_count = reader.integer()
    children = [_read_proto(reader) for _ in range(proto_count)]

    # отладочная информация
    lineinfo_count = reader.integer()
    if lineinfo_count:
        reader.bytes(lineinfo_count * reader.int_size)
    locvars_count = reader.integer()
    for _ in range(locvars_count):
        reader.string()
        reader.integer()
        reader.integer()
    upvalues_count = reader.integer()
    for _ in range(upvalues_count):
        reader.string()

    return _Proto(
        source=(source or b"").decode("utf-8", "replace") if source else None,
        line_defined=line_defined,
        line_last=line_last,
        code_offset=code_offset,
        code_count=code_count,
        constants=constants,
        const_offsets=const_offsets,
        children=children,
        consts_count_offset=consts_count_offset,
        consts_end=consts_end,
        consts_start=consts_start,
    )


def _walk(proto: _Proto, prefix: str = "main"):
    yield prefix, proto
    for index, child in enumerate(proto.children):
        yield from _walk(child, "%s.%d" % (prefix, index))


def _instructions(data: bytes, proto: _Proto, endian: str) -> List[int]:
    raw = data[proto.code_offset:proto.code_offset + proto.code_count * 4]
    fmt = "<" if endian == "little" else ">"
    return list(struct.unpack("%s%dI" % (fmt, proto.code_count), raw))


def _flag_const_indexes(proto: _Proto) -> dict:
    """Словарь «индекс константы -> имя флага» для нужных флагов."""
    found: dict = {}
    for index, (kind, value) in enumerate(proto.constants):
        if kind != 4 or not isinstance(value, str):
            continue
        name = value.rsplit(".", 1)[-1]
        if name in FLAG_NAMES:
            found.setdefault(index, name)
    return found


OP_LOADK = 1
OP_NEWTABLE = 10
OP_CLOSURE = 36


def _find_assignment(instructions: Sequence[int], pc: int, known: dict):
    """Найти присваивание флагу: вернуть (имя флага, источник значения)."""
    instr = instructions[pc]
    opcode = instr & 0x3F
    if opcode == OP_SETTABLE:
        # R(A)[RK(B)] := RK(C): ключ — RK(B), значение — RK(C)
        b_rk = (instr >> 23) & 0x1FF
        c_rk = (instr >> 14) & 0x1FF
        key_index = b_rk & MAXINDEXRK
        if (b_rk & BITRK) and key_index in known:
            return known[key_index], c_rk
    elif opcode == OP_SETGLOBAL:
        # R(A) — значение, Bx — индекс константы с именем глобальной переменной
        bx = (instr >> 14) & 0x3FFFF
        if bx in known:
            return known[bx], (instr >> 6) & 0xFF
    return None, None


def _resolve_value(instructions: Sequence[int], pc: int, value_rk: int):
    """Разобраться, откуда берётся значение.

    Возвращает тройку (вид, номер инструкции-источника, значение):

    * ``("const", номер, индекс константы)`` — значение лежит в таблице констант;
    * ``("loadbool", номер, True/False)`` — значение грузится инструкцией LOADBOOL;
    * ``(None, None, None)`` — не разобрались.
    """
    if value_rk & BITRK:
        # значение уже в самой инструкции присваивания (RK-операнд)
        return "const", pc, value_rk & MAXINDEXRK
    register = value_rk
    for back in range(1, 16):
        index = pc - back
        if index < 0:
            break
        instr = instructions[index]
        opcode = instr & 0x3F
        if opcode == OP_LOADBOOL and ((instr >> 6) & 0xFF) == register:
            return "loadbool", index, bool((instr >> 23) & 0x1FF)
        if opcode == OP_LOADK and ((instr >> 6) & 0xFF) == register:
            return "const", index, (instr >> 14) & 0x3FFFF
    return None, None, None


def _constant_references(instructions: Sequence[int]) -> dict:
    """Сколько раз каждая константа упоминается в инструкциях прототипа."""
    counts: dict = {}

    def bump(index: int) -> None:
        counts[index] = counts.get(index, 0) + 1

    for instr in instructions:
        opcode = instr & 0x3F
        if opcode in (OP_LOADK, OP_GETGLOBAL, OP_SETGLOBAL, OP_CLOSURE):
            bump((instr >> 14) & 0x3FFFF)
        # RK-операнды: B и C почти у всех iABC-инструкций
        for shift in (23, 14):
            rk = (instr >> shift) & 0x1FF
            if rk & BITRK:
                bump(rk & MAXINDEXRK)
    return counts


def _find_false_constant(proto: _Proto) -> Optional[int]:
    """Индекс уже существующей константы `false` в прототипе."""
    for index, (kind, value) in enumerate(proto.constants):
        if kind == 1 and value is False:
            return index
    return None


def _patch_bytecode(data: bytes) -> PatchResult:
    """Правка флагов прямо в байткоде Lua 5.1 (без декомпиляции).

    Работает в трёх ситуациях:

    * значение грузится инструкцией ``LOADBOOL`` — правим B (true -> false);
    * значение берётся из таблицы констант — тогда либо переворачиваем саму
      константу (если больше никто на неё не ссылается), либо добавляем в
      таблицу константу ``false`` и переводим присваивание на неё
      (формат чанка не хранит абсолютных адресов, поэтому вставка безопасна).
    """
    reader, proto = _parse_chunk(data)
    fmt = "<" if reader.endian == "little" else ">"
    edits: List[Tuple[int, bytes]] = []          # (смещение, новые байты)
    insertions: List[Tuple[int, bytes]] = []     # (смещение, вставка)
    changes: List[Change] = []
    already: List[str] = []
    touched: set = set()
    inserted_false: dict = {}                    # proto id -> индекс новой константы

    for label, current in _walk(proto):
        known = _flag_const_indexes(current)
        if not known:
            continue
        instructions = _instructions(data, current, reader.endian)
        refs = _constant_references(instructions)

        for pc in range(len(instructions)):
            flag_name, value_rk = _find_assignment(instructions, pc, known)
            if flag_name is None:
                continue
            kind, source_pc, value = _resolve_value(instructions, pc, value_rk)

            if kind == "loadbool":
                if value is False:
                    already.append(flag_name)
                    touched.add(flag_name)
                    continue
                a = (instructions[source_pc] >> 6) & 0xFF
                new_instr = OP_LOADBOOL | (a << 6)
                edits.append(
                    (current.code_offset + source_pc * 4, struct.pack(fmt + "I", new_instr))
                )
                changes.append(
                    Change(
                        flag_name,
                        "true",
                        "false",
                        "%s, инструкция LOADBOOL №%d" % (label, source_pc),
                    )
                )
                touched.add(flag_name)
                continue

            if kind == "const":
                const_index = value
                if current.constant_type(const_index) != 1:
                    continue  # не булева константа — не наш случай
                if current.constant_value(const_index) is False:
                    already.append(flag_name)
                    touched.add(flag_name)
                    continue
                if refs.get(const_index, 0) <= 1:
                    # константа встречается только здесь — переворачиваем её
                    edits.append((current.const_offsets[const_index] + 1, b"\x00"))
                    changes.append(
                        Change(
                            flag_name,
                            "true",
                            "false",
                            "%s, константа №%d" % (label, const_index),
                        )
                    )
                    touched.add(flag_name)
                    continue
                # константа общая для нескольких мест — заводим отдельную false
                false_index = _find_false_constant(current)
                if false_index is None:
                    if id(current) not in inserted_false:
                        new_index = len(current.constants)
                        if new_index > MAXINDEXRK:
                            raise BytecodeError(
                                "В таблице констант уже 256 элементов — "
                                "автоматическая правка невозможна"
                            )
                        insertions.append((current.consts_end, b"\x01\x00"))
                        edits.append(
                            (
                                current.consts_count_offset,
                                struct.pack(fmt + "i", len(current.constants) + 1),
                            )
                        )
                        inserted_false[id(current)] = new_index
                    false_index = inserted_false[id(current)]
                opcode = instructions[source_pc] & 0x3F
                if opcode == OP_SETTABLE:
                    new_instr = (instructions[source_pc] & ~(0x1FF << 14)) | (
                        (BITRK | false_index) << 14
                    )
                else:  # LOADK
                    new_instr = (instructions[source_pc] & ~(0x3FFFF << 14)) | (
                        false_index << 14
                    )
                edits.append(
                    (current.code_offset + source_pc * 4, struct.pack(fmt + "I", new_instr))
                )
                changes.append(
                    Change(
                        flag_name,
                        "true",
                        "false",
                        "%s, константа №%d -> №%d"
                        % (label, const_index, false_index),
                    )
                )
                touched.add(flag_name)

    # Применяем правки от конца файла к началу, чтобы смещения не «поехали»
    operations = [(offset, data_bytes, False) for offset, data_bytes in edits]
    operations += [(offset, data_bytes, True) for offset, data_bytes in insertions]
    operations.sort(key=lambda item: item[0], reverse=True)
    buf = bytearray(data)
    for offset, payload, is_insert in operations:
        if is_insert:
            buf[offset:offset] = payload
        else:
            buf[offset:offset + len(payload)] = payload

    result = PatchResult(
        data=bytes(buf),
        kind=KIND_LUA_BYTECODE,
        changes=changes,
        already_off=sorted(set(already)),
    )
    result.missing = [name for name in FLAG_NAMES if name not in touched]
    return result


def _bytecode_flags_state(data: bytes) -> dict:
    """Текущие значения флагов в байткоде."""
    try:
        reader, proto = _parse_chunk(data)
    except BytecodeError:
        return {}
    state: dict = {}
    for _label, current in _walk(proto):
        known = _flag_const_indexes(current)
        if not known:
            continue
        instructions = _instructions(data, current, reader.endian)
        for pc in range(len(instructions)):
            flag_name, value_rk = _find_assignment(instructions, pc, known)
            if flag_name is None:
                continue
            kind, _source_pc, value = _resolve_value(instructions, pc, value_rk)
            if kind == "loadbool":
                state[flag_name] = "true" if value else "false"
            elif kind == "const":
                if current.constant_type(value) == 1:
                    state[flag_name] = "true" if current.constant_value(value) else "false"
    return state


# --------------------------------------------------------------------------
# Точка входа
# --------------------------------------------------------------------------

def patch(data: bytes) -> PatchResult:
    """Выключить флаги регистрации/обновления в файле (текст, JSON или байткод)."""
    kind = detect_kind(data)
    if kind == KIND_LUA_TEXT:
        return _patch_text(data)
    if kind == KIND_JSON:
        return _patch_json(data)
    if kind == KIND_LUA_BYTECODE:
        return _patch_bytecode(data)
    if kind == KIND_LUAJIT:
        raise BytecodeError(
            "Это байткод LuaJIT — правка инструкций не поддерживается. "
            "Декомпилируйте файл через luajit-decompiler или используйте "
            "unluac для обычного Lua 5.1."
        )
    raise BytecodeError(
        "Не удалось определить формат содержимого (не текст Lua, не JSON, не байткод). "
        "Возможно, выбран неверный ключ или файл не является скриптом."
    )


# --------------------------------------------------------------------------
# Необязательный путь через unluac (как в гайде)
# --------------------------------------------------------------------------

def find_unluac_jar() -> Optional[str]:
    """Найти unluac.jar: переменная окружения, папка tools или PATH."""
    env = os.environ.get("ABLUA_UNLUAC_JAR")
    if env and os.path.isfile(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), "tools", "unluac.jar"),
        os.path.join(here, "unluac.jar"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def decompile(data: bytes) -> str:
    """Декомпилировать байткод через unluac.jar (нужна Java)."""
    jar = find_unluac_jar()
    if not jar:
        raise BytecodeError(
            "unluac.jar не найден. Положите его в папку tools/ или укажите "
            "переменную окружения ABLUA_UNLUAC_JAR (файл не обязателен: "
            "активация работает и без декомпиляции)."
        )
    try:
        result = subprocess.run(
            ["java", "-jar", jar],
            input=data,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise BytecodeError("Java не найдена в PATH — без неё unluac не запустить") from exc
    if result.returncode != 0:
        raise BytecodeError(
            "unluac завершился с ошибкой: %s"
            % (result.stderr.decode("utf-8", "replace").strip() or "без сообщения")
        )
    return result.stdout.decode("utf-8", "replace")
