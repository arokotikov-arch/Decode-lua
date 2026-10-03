"""Минимальная реализация формата 7z (только то, что нужно игре).

Angry Birds PC хранит `options.lua` внутри 7z-архива (после расшифровки
первые два байта файла — `7z`). Внешние утилиты (7za.exe и т.п.) тащить
с собой не хочется, поэтому здесь есть свой разбор и своя запись архива
на чистом Python (сжатие — через стандартный модуль `lzma`).

Поддерживается чтение: Copy, LZMA (0x030101), LZMA2 (0x21), BCJ x86 (0x03030103),
многофайловые/многопоточные ("solid") архивы.
Запись: однопоточный (solid) архив с одним файлом, метод LZMA2.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "SevenZipError",
    "SevenZipEntry",
    "is_7z",
    "read_archive",
    "create_archive",
    "list_names",
]

SIGNATURE = b"7z\xbc\xaf\x27\x1c"
_HEADER_SIZE = 32

# Идентификаторы свойств
K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPERTIES = 0x02
K_ADDITIONAL_STREAMS_INFO = 0x03
K_MAIN_STREAMS_INFO = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_EMPTY_FILE = 0x0F
K_ANTI = 0x10
K_NAME = 0x11
K_CTIME = 0x12
K_ATIME = 0x13
K_MTIME = 0x14
K_WIN_ATTRIBUTES = 0x15
K_ENCODED_HEADER = 0x17
K_DUMMY = 0x19

# Идентификаторы методов сжатия
M_COPY = b"\x00"
M_LZMA = b"\x03\x01\x01"
M_LZMA2 = b"\x21"
M_BCJ_X86 = b"\x03\x03\x01\x03"
M_BCJ_ARM = b"\x03\x03\x05\x01"
M_DELTA = b"\x03"


class SevenZipError(Exception):
    """Ошибка разбора/сборки 7z-архива."""


@dataclass
class SevenZipEntry:
    name: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


# --------------------------------------------------------------------------
# Чтение
# --------------------------------------------------------------------------

class _Cursor:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def byte(self) -> int:
        if self.pos >= len(self.buf):
            raise SevenZipError("Неожиданный конец заголовка 7z")
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise SevenZipError("Неожиданный конец заголовка 7z")
        v = self.buf[self.pos:self.pos + n]
        self.pos += n
        return v

    def number(self) -> int:
        """7z-число переменной длины."""
        first = self.byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if not (first & mask):
                value |= (first & (mask - 1)) << (8 * i)
                return value
            value |= self.byte() << (8 * i)
            mask >>= 1
        return value

    def uint32(self) -> int:
        return struct.unpack("<I", self.bytes(4))[0]

    def boolean_bits(self, count: int) -> List[bool]:
        """Упакованный битовый вектор (как в 7z)."""
        bits: List[bool] = []
        b = 0
        mask = 0
        for _ in range(count):
            if mask == 0:
                b = self.byte()
                mask = 0x80
            bits.append(bool(b & mask))
            mask >>= 1
        return bits

    def digests(self, count: int) -> List[Optional[int]]:
        all_defined = self.byte()
        defined = [True] * count if all_defined else self.boolean_bits(count)
        out: List[Optional[int]] = []
        for d in defined:
            out.append(self.uint32() if d else None)
        return out


@dataclass
class _Coder:
    method: bytes
    props: bytes
    num_in: int
    num_out: int


@dataclass
class _Folder:
    coders: List[_Coder]
    bind_pairs: List[Tuple[int, int]]
    packed_indices: List[int]
    unpack_sizes: List[int] = None  # type: ignore[assignment]

    @property
    def num_out_streams(self) -> int:
        return sum(c.num_out for c in self.coders)

    @property
    def num_in_streams(self) -> int:
        return sum(c.num_in for c in self.coders)

    def result_out_index(self) -> int:
        """Глобальный индекс выходного потока, который является результатом блока."""
        bound_outs = {pair[1] for pair in self.bind_pairs}
        for gi in range(self.num_out_streams):
            if gi not in bound_outs:
                return gi
        return self.num_out_streams - 1

    def total_unpack_size(self) -> int:
        return self.unpack_sizes[self.result_out_index()]

    def packed_input_index(self) -> int:
        """Индекс входного потока, который приходит из упакованных данных."""
        bound_inputs = {pair[0] for pair in self.bind_pairs}
        for index in range(self.num_in_streams):
            if index not in bound_inputs:
                return index
        return 0

    def ordered_coders(self) -> List["_Coder"]:
        """Кодеры в порядке прохождения данных: от упакованных данных к результату."""
        in_owner: Dict[int, int] = {}
        gi = 0
        for ci, coder in enumerate(self.coders):
            for _ in range(coder.num_in):
                in_owner[gi] = ci
                gi += 1
        out_owner: Dict[int, int] = {}
        gi = 0
        for ci, coder in enumerate(self.coders):
            for _ in range(coder.num_out):
                out_owner[gi] = ci
                gi += 1

        out_to_in = {out: inp for inp, out in self.bind_pairs}

        current = in_owner.get(self.packed_input_index())
        if current is None:
            raise SevenZipError("Не удалось определить начало цепочки кодеков 7z")
        order: List[_Coder] = []
        seen = set()
        while current is not None and current not in seen:
            seen.add(current)
            coder = self.coders[current]
            order.append(coder)
            # выходной поток этого кодера
            out_gi = None
            gi = 0
            for ci, c in enumerate(self.coders):
                if ci == current:
                    out_gi = gi
                    break
                gi += c.num_out
            if out_gi is None:
                break
            next_in = out_to_in.get(out_gi)
            current = in_owner.get(next_in) if next_in is not None else None
        if len(order) != len(self.coders):
            raise SevenZipError(
                "Сложная схема кодеков 7z не поддерживается (%d из %d)"
                % (len(order), len(self.coders))
            )
        return order

    def filter_chain(self) -> List[dict]:
        """Цепочка фильтров lzma в порядке кодирования (для FORMAT_RAW).

        Модуль lzma ожидает фильтры в порядке кодирования (сначала внешний
        фильтр вроде BCJ, затем сжимающий), а в 7z кодеры перечислены со
        стороны упакованных данных — поэтому список переворачивается.
        """
        filters: List[dict] = []
        for coder in reversed(self.ordered_coders()):
            if coder.method == M_COPY:
                continue
            filters.append(_coder_filter(coder))
        if not filters:
            raise SevenZipError("Блок 7z без поддерживаемого метода сжатия")
        return filters


def is_7z(data: bytes) -> bool:
    """Похоже ли начало файла на 7z-архив (игра проверяет именно префикс «7z»)."""
    return data[:6] == SIGNATURE or data[:2] == b"7z"


def _read_folder(cur: _Cursor) -> _Folder:
    num_coders = cur.number()
    coders: List[_Coder] = []
    total_in = 0
    total_out = 0
    for _ in range(num_coders):
        flags = cur.byte()
        id_size = flags & 0x0F
        method = cur.bytes(id_size)
        if flags & 0x10:  # сложный кодер
            num_in = cur.number()
            num_out = cur.number()
        else:
            num_in = num_out = 1
        props = b""
        if flags & 0x20:  # есть свойства
            props_size = cur.number()
            props = cur.bytes(props_size)
        coders.append(_Coder(method, props, num_in, num_out))
        total_in += num_in
        total_out += num_out

    num_bind_pairs = total_out - 1
    bind_pairs = [(cur.number(), cur.number()) for _ in range(num_bind_pairs)]
    num_packed = total_in - num_bind_pairs
    if num_packed == 1:
        packed_indices = [0]
    elif num_packed > 1:
        packed_indices = [cur.number() for _ in range(num_packed)]
    else:
        packed_indices = []
    return _Folder(coders, bind_pairs, packed_indices)


def _read_streams_info(cur: _Cursor) -> Dict[str, object]:
    info: Dict[str, object] = {
        "pack_pos": 0,
        "pack_sizes": [],
        "folders": [],
        "substream_sizes": [],
    }
    prop = cur.byte()
    if prop == K_END:
        return info
    if prop != K_PACK_INFO:
        raise SevenZipError("Ожидался блок PackInfo, получено 0x%02X" % prop)

    info["pack_pos"] = cur.number()
    num_pack = cur.number()
    while True:
        prop = cur.byte()
        if prop == K_END:
            break
        if prop == K_SIZE:
            info["pack_sizes"] = [cur.number() for _ in range(num_pack)]
        elif prop == K_CRC:
            cur.digests(num_pack)
        else:
            raise SevenZipError("Неизвестное свойство PackInfo 0x%02X" % prop)

    prop = cur.byte()
    if prop == K_END:
        return info
    if prop != K_UNPACK_INFO:
        raise SevenZipError("Ожидался блок UnpackInfo, получено 0x%02X" % prop)

    if cur.byte() != K_FOLDER:
        raise SevenZipError("Ожидался блок Folder")
    num_folders = cur.number()
    external = cur.byte()
    if external:
        raise SevenZipError("Внешние данные 7z не поддерживаются")
    folders = [_read_folder(cur) for _ in range(num_folders)]

    if cur.byte() != K_CODERS_UNPACK_SIZE:
        raise SevenZipError("Ожидался блок CodersUnpackSize")
    for folder in folders:
        folder.unpack_sizes = [cur.number() for _ in range(folder.num_out_streams)]

    folder_crc_defined = [False] * num_folders
    while True:
        prop = cur.byte()
        if prop == K_END:
            break
        if prop == K_CRC:
            folder_crc_defined = [d is not None for d in cur.digests(num_folders)]
        else:
            raise SevenZipError("Неизвестное свойство UnpackInfo 0x%02X" % prop)

    info["folders"] = folders

    # --- SubStreamsInfo (необязательно) ---
    num_unpack_streams = [1] * num_folders
    raw_sizes: List[int] = []
    prop = cur.byte()
    if prop == K_SUBSTREAMS_INFO:
        while True:
            prop = cur.byte()
            if prop == K_END:
                break
            if prop == K_NUM_UNPACK_STREAM:
                num_unpack_streams = [cur.number() for _ in range(num_folders)]
            elif prop == K_SIZE:
                count = sum(max(0, n - 1) for n in num_unpack_streams)
                raw_sizes = [cur.number() for _ in range(count)]
            elif prop == K_CRC:
                # количество CRC: для блоков с одним подпотоком и уже известной
                # CRC блока дайджест не дублируется
                count = 0
                for i, n in enumerate(num_unpack_streams):
                    if n != 1 or not folder_crc_defined[i]:
                        count += n
                cur.digests(count)
            else:
                raise SevenZipError("Неизвестное свойство SubStreamsInfo 0x%02X" % prop)
        # завершающий байт самого StreamsInfo
        prop = cur.byte()
        if prop != K_END:
            raise SevenZipError("Ожидался конец StreamsInfo")
    elif prop != K_END:
        raise SevenZipError("Неожиданное свойство StreamsInfo 0x%02X" % prop)

    # Разворачиваем размеры подпотоков: последний в блоке вычисляется по остатку
    per_folder: List[List[int]] = []
    pos = 0
    for i, folder in enumerate(folders):
        n = num_unpack_streams[i]
        if n <= 0:
            per_folder.append([])
            continue
        if n == 1:
            per_folder.append([folder.total_unpack_size()])
            continue
        sizes = raw_sizes[pos:pos + n - 1]
        pos += n - 1
        if len(sizes) != n - 1:
            raise SevenZipError("Недостаточно размеров подпотоков в 7z")
        last = folder.total_unpack_size() - sum(sizes)
        if last < 0:
            raise SevenZipError("Некорректные размеры подпотоков в 7z")
        per_folder.append(sizes + [last])

    info["substreams_per_folder"] = per_folder
    info["substream_sizes"] = [s for sizes in per_folder for s in sizes]
    return info


def _decode_streams(
    streams: Dict[str, object], blob: bytes
) -> List[bytes]:
    """Распаковывает потоки одного StreamsInfo в список подпотоков.

    Данные упакованных потоков всегда лежат сразу после заголовка подписи
    (смещение 32), поэтому смещение считается от него.
    """
    pack_pos: int = streams["pack_pos"]  # type: ignore[assignment]
    pack_sizes: Sequence[int] = streams["pack_sizes"]  # type: ignore[assignment]
    folders: List[_Folder] = streams["folders"]  # type: ignore[assignment]
    per_folder: Sequence[Sequence[int]] = streams["substreams_per_folder"]  # type: ignore[assignment]

    pack_offsets: List[int] = []
    acc = _HEADER_SIZE + pack_pos
    for size in pack_sizes:
        pack_offsets.append(acc)
        acc += size

    streams_data: List[bytes] = []
    for index, folder in enumerate(folders):
        chunks = []
        for pack_index in folder.packed_indices:
            if pack_index >= len(pack_sizes):
                raise SevenZipError("Ссылка на несуществующий поток 7z")
            start = pack_offsets[pack_index]
            chunks.append(blob[start:start + pack_sizes[pack_index]])
        packed = b"".join(chunks)
        raw = _decode_folder(folder, packed)
        sizes = list(per_folder[index]) if index < len(per_folder) else [len(raw)]
        if not sizes:
            continue
        if sum(sizes) != len(raw):
            raise SevenZipError("Размеры подпотоков не совпадают с размером блока 7z")
        cut = 0
        for size in sizes:
            streams_data.append(raw[cut:cut + size])
            cut += size
    return streams_data


def _read_header(blob: bytes, container: Optional[bytes] = None) -> Dict[str, object]:
    cur = _Cursor(blob)
    first = cur.byte()
    if first == K_ENCODED_HEADER:
        # Заголовок 7z сам упакован (так делают по умолчанию 7-Zip и py7zr):
        # далее идёт StreamsInfo с упакованным заголовком.
        if container is None:
            raise SevenZipError("Сжатый заголовок 7z требует доступа к файлу целиком")
        streams = _read_streams_info(cur)
        parts = _decode_streams(streams, container)
        decoded = b"".join(parts)
        return _read_header(decoded, container)
    if first != K_HEADER:
        raise SevenZipError("Повреждённый заголовок 7z")

    result: Dict[str, object] = {
        "streams": None,
        "names": [],
        "empties": [],
        "empty_files": [],
        "anti": [],
    }
    while True:
        prop = cur.byte()
        if prop == K_END:
            break
        if prop == K_ARCHIVE_PROPERTIES:
            while True:
                ap = cur.byte()
                if ap == K_END:
                    break
                size = cur.number()
                cur.bytes(size)
        elif prop == K_ADDITIONAL_STREAMS_INFO:
            _read_streams_info(cur)
        elif prop == K_MAIN_STREAMS_INFO:
            result["streams"] = _read_streams_info(cur)
        elif prop == K_FILES_INFO:
            num_files = cur.number()
            names: List[str] = []
            empties: List[bool] = [False] * num_files
            empty_files: List[bool] = []
            anti: List[bool] = [False] * num_files
            while True:
                fp = cur.byte()
                if fp == K_END:
                    break
                size = cur.number()
                end_pos = cur.pos + size
                if fp == K_EMPTY_STREAM:
                    empties = cur.boolean_bits(num_files)
                elif fp == K_EMPTY_FILE:
                    # биты только для потоков, отмеченных как пустые:
                    # 1 = пустой файл, 0 = каталог
                    empty_files = cur.boolean_bits(sum(empties))
                elif fp == K_ANTI:
                    bits = cur.boolean_bits(sum(empties))
                    it = iter(bits)
                    anti = [next(it) if e else False for e in empties]
                elif fp == K_NAME:
                    external = cur.byte()
                    if external:
                        raise SevenZipError("Внешние имена 7z не поддерживаются")
                    raw = cur.bytes(end_pos - cur.pos)
                    text = raw.decode("utf-16-le", "replace")
                    if text.endswith("\x00"):
                        text = text[:-1]
                    names = text.split("\x00") if text else []
                else:
                    cur.bytes(end_pos - cur.pos)
                cur.pos = end_pos
            result["names"] = names
            result["empties"] = empties
            result["empty_files"] = empty_files
            result["anti"] = anti
        else:
            raise SevenZipError("Неизвестное свойство заголовка 7z 0x%02X" % prop)
    return result


def _coder_filter(coder: _Coder) -> dict:
    """Описание одного кодера 7z в терминах фильтров модуля lzma."""
    if coder.method == M_LZMA:
        return _lzma1_filter(coder.props)
    if coder.method == M_LZMA2:
        return {"id": lzma.FILTER_LZMA2, "dict_size": lzma2_dict_size(coder.props)}
    if coder.method == M_BCJ_X86:
        spec = {"id": lzma.FILTER_X86}
        if len(coder.props) >= 4:
            spec["start_offset"] = struct.unpack("<I", coder.props[:4])[0]
        return spec
    if coder.method == M_BCJ_ARM:
        return {"id": lzma.FILTER_ARM}
    if coder.method == M_DELTA:
        dist = coder.props[0] + 1 if coder.props else 1
        return {"id": lzma.FILTER_DELTA, "dist": max(1, min(256, dist))}
    raise SevenZipError("Метод сжатия 7z %s не поддерживается" % coder.method.hex())


def _decode_folder(folder: _Folder, packed_blob: bytes) -> bytes:
    """Распаковка данных одного блока (folder)."""
    out_size = folder.total_unpack_size()
    flow = folder.ordered_coders()

    if not any(c.method in (M_LZMA, M_LZMA2) for c in flow):
        # только фильтры предобработки (например, чистый BCJ без сжатия):
        # lzma такое не умеет, поэтому раскручиваем вручную
        data = packed_blob
        for coder in flow:
            if coder.method == M_COPY:
                continue
            if coder.method == M_BCJ_X86:
                offset = struct.unpack("<I", coder.props[:4])[0] if len(coder.props) >= 4 else 0
                data = _bcj_x86_decode(data, offset)
            elif coder.method == M_BCJ_ARM:
                raise SevenZipError("Чистый BCJ-ARM без сжатия не поддерживается")
            else:
                raise SevenZipError(
                    "Метод сжатия 7z %s не поддерживается" % coder.method.hex()
                )
    else:
        filters = folder.filter_chain()
        try:
            data = lzma.decompress(packed_blob, format=lzma.FORMAT_RAW, filters=filters)
        except lzma.LZMAError as exc:
            raise SevenZipError("Не удалось распаковать блок 7z: %s" % exc) from exc
    if out_size and len(data) != out_size:
        raise SevenZipError(
            "Размер распакованных данных не совпал: %d != %d" % (len(data), out_size)
        )
    return data


def _bcj_x86_decode(data: bytes, start_offset: int) -> bytes:
    """Декодер фильтра BCJ (x86) — на случай архива без сжатия."""
    out = bytearray(data)
    size = len(out)
    i = 0
    while i + 4 < size:
        if out[i] == 0xE8 or out[i] == 0xE9:
            rel = int.from_bytes(out[i + 1:i + 5], "little", signed=True)
            rel -= (i + 5) + start_offset
            out[i + 1:i + 5] = (rel & 0xFFFFFFFF).to_bytes(4, "little")
            i += 5
        else:
            i += 1
    return bytes(out)


def lzma2_dict_size(props: bytes) -> int:
    """Размер словаря LZMA2 из байта свойств кодера."""
    if not props:
        return 1 << 24
    p = props[0]
    if p > 40:
        return 0xFFFFFFFF
    return (2 | (p & 1)) << (p // 2 + 11)


def lzma2_props(dict_size: int) -> bytes:
    """Байт свойств LZMA2 для заданного размера словаря."""
    for p in range(0, 41):
        if (2 | (p & 1)) << (p // 2 + 11) == dict_size:
            return bytes([p])
    raise SevenZipError("Неподдерживаемый размер словаря LZMA2: %d" % dict_size)


def _lzma1_filter(props: bytes) -> dict:
    """Фильтр LZMA1: 1 байт свойств + 4 байта размера словаря."""
    if len(props) < 5:
        return {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 24}
    dict_size = struct.unpack("<I", props[1:5])[0]
    lc = props[0] % 9
    rest = props[0] // 9
    lp = rest % 5
    pb = rest // 5
    return {
        "id": lzma.FILTER_LZMA1,
        "dict_size": max(dict_size, 4096),
        "lc": lc,
        "lp": lp,
        "pb": pb,
    }


def read_archive(blob: bytes) -> List[SevenZipEntry]:
    """Читает 7z-архив и возвращает список файлов (без каталогов)."""
    if not is_7z(blob):
        raise SevenZipError("Это не 7z-архив")
    if len(blob) < _HEADER_SIZE:
        raise SevenZipError("Файл слишком короткий для 7z")

    next_offset = struct.unpack("<Q", blob[12:20])[0]
    next_size = struct.unpack("<Q", blob[20:28])[0]
    header_start = _HEADER_SIZE + next_offset
    header = blob[header_start:header_start + next_size]
    if len(header) != next_size:
        raise SevenZipError("Заголовок 7z выходит за пределы файла")

    parsed = _read_header(header, container=blob)
    streams = parsed["streams"]  # type: ignore[index]
    names: List[str] = parsed["names"]  # type: ignore[assignment]
    empties: List[bool] = parsed["empties"]  # type: ignore[assignment]
    anti: List[bool] = parsed["anti"]  # type: ignore[assignment]
    empty_files: List[bool] = parsed["empty_files"]  # type: ignore[assignment]

    if not streams:
        # архив без потоков — только каталоги/пустые файлы
        return []

    streams_data = _decode_streams(streams, blob)  # type: ignore[arg-type]

    # Раскладываем подпотоки по файлам в порядке записи
    file_stream_index = 0
    entries: List[SevenZipEntry] = []
    for i, name in enumerate(names):
        is_empty = empties[i] if i < len(empties) else False
        is_anti = anti[i] if i < len(anti) else False
        if is_anti:
            continue
        if is_empty:
            if i < len(empty_files) and empty_files[i]:
                entries.append(SevenZipEntry(name, b""))
            continue  # иначе это каталог — пропускаем
        if file_stream_index >= len(streams_data):
            raise SevenZipError("Файлов больше, чем потоков в 7z")
        entries.append(SevenZipEntry(name, streams_data[file_stream_index]))
        file_stream_index += 1

    return entries


def list_names(blob: bytes) -> List[str]:
    return [e.name for e in read_archive(blob)]


# --------------------------------------------------------------------------
# Запись
# --------------------------------------------------------------------------

class _Writer:
    def __init__(self) -> None:
        self.buf = bytearray()

    def byte(self, value: int) -> None:
        self.buf.append(value & 0xFF)

    def bytes(self, value: bytes) -> None:
        self.buf += value

    def number(self, value: int) -> None:
        """Запись 7z-числа переменной длины."""
        if value < 0:
            raise SevenZipError("Отрицательные числа недопустимы")
        first = 0
        mask = 0x80
        extra = bytearray()
        for i in range(8):
            if value < (1 << (7 * (i + 1))):
                first |= value >> (8 * i)
                break
            first |= mask
            extra.append((value >> (8 * i)) & 0xFF)
            mask >>= 1
        else:
            first = 0xFF
            extra = bytearray((value >> (8 * i)) & 0xFF for i in range(8))
        self.byte(first)
        self.bytes(bytes(extra))

    def uint32(self, value: int) -> None:
        self.bytes(struct.pack("<I", value & 0xFFFFFFFF))


def create_archive(name: str, data: bytes, dict_size: int = 1 << 24) -> bytes:
    """Собирает 7z-архив с одним файлом `name` (сжатие LZMA2).

    Формат максимально простой, но полностью валидный: игра (и любой
    другой распаковщик 7z) читает его штатно.
    """
    filters = [{
        "id": lzma.FILTER_LZMA2,
        "dict_size": dict_size,
        "lc": 3,
        "lp": 0,
        "pb": 2,
    }]
    packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    header = _build_header(name, data, packed, dict_size)

    out = bytearray()
    out += SIGNATURE
    out += bytes([0, 4])                                   # версия формата
    start_header = struct.pack(
        "<QQI",
        len(packed),          # смещение следующего заголовка
        len(header),          # размер следующего заголовка
        zlib.crc32(header),
    )
    out += struct.pack("<I", zlib.crc32(start_header))
    out += start_header
    out += packed
    out += header
    return bytes(out)


def _build_header(name: str, data: bytes, packed: bytes, dict_size: int) -> bytes:
    w = _Writer()
    w.byte(K_HEADER)

    # --- MainStreamsInfo ---
    w.byte(K_MAIN_STREAMS_INFO)

    # PackInfo
    w.byte(K_PACK_INFO)
    w.number(0)                    # packPos (сразу после заголовка подписи)
    w.number(1)                    # число упакованных потоков
    w.byte(K_SIZE)
    w.number(len(packed))
    w.byte(K_CRC)
    w.byte(1)                      # все CRC определены
    w.uint32(zlib.crc32(packed))
    w.byte(K_END)

    # UnpackInfo
    w.byte(K_UNPACK_INFO)
    w.byte(K_FOLDER)
    w.number(1)                    # число блоков
    w.byte(0)                      # external = 0

    w.number(1)                    # число кодеров в блоке
    flags = 0x01 | 0x20            # один байт идентификатора + есть свойства
    w.byte(flags)
    w.bytes(M_LZMA2)
    w.number(1)                    # размер свойств
    w.bytes(lzma2_props(dict_size))

    # Связки потоков (bind pairs) в формате не нумеруются: их количество
    # вычисляется как (число выходных потоков - 1). У нас один кодер,
    # поэтому связок нет, а упакованный поток ровно один — индексы не пишутся.

    w.byte(K_CODERS_UNPACK_SIZE)
    w.number(len(data))
    w.byte(K_CRC)
    w.byte(1)
    w.uint32(zlib.crc32(data))
    w.byte(K_END)

    # SubStreamsInfo: один подпоток = весь блок, свойств нет
    w.byte(K_SUBSTREAMS_INFO)
    w.byte(K_END)

    w.byte(K_END)                  # конец StreamsInfo

    # --- FilesInfo ---
    w.byte(K_FILES_INFO)
    w.number(1)                    # один файл
    encoded_name = name.encode("utf-16-le") + b"\x00\x00"
    w.byte(K_NAME)
    w.number(1 + len(encoded_name))  # размер свойства (external + строка)
    w.byte(0)                      # external = 0
    w.bytes(encoded_name)
    w.byte(K_END)                  # конец FilesInfo

    w.byte(K_END)                  # конец заголовка
    return bytes(w.buf)
