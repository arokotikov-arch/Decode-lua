"""AES-256-CBC + PKCS#7 — совместимо с OpenSSL (`openssl enc -aes-256-cbc -iv 00`).

Тот же алгоритм используют AB360 LUA Manager и LevelAutoEnc:
ключ — 32 ASCII-символа (256 бит), IV — нулевой, дополнение — PKCS#7.

Модуль работает без внешних зависимостей: если установлен пакет
`cryptography` или `pycryptodome`, используется быстрый путь, иначе —
чистая реализация на Python (медленнее, но результат побайтово тот же).
"""

from __future__ import annotations

from typing import Tuple

__all__ = [
    "BLOCK_SIZE",
    "expand_key",
    "encrypt_block",
    "decrypt_block",
    "encrypt_cbc_nopad",
    "decrypt_cbc_nopad",
    "pad",
    "unpad",
    "encrypt",
    "decrypt",
    "backend_name",
]

BLOCK_SIZE = 16
_KEY_SIZE = 32  # AES-256


# --------------------------------------------------------------------------
# Таблицы (генерируются математически, чтобы не тащить их списком)
# --------------------------------------------------------------------------

def _rotl8(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _build_sboxes() -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """S-бокс и обратный S-бокс для GF(2^8)."""
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        # p := p * 3  (в GF(2^8))
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        # q := q / 3  (умножение на 0xF6 == деление на 3)
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = xformed ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63

    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return tuple(sbox), tuple(inv_sbox)


SBOX, INV_SBOX = _build_sboxes()

# Проверка самопроверки таблиц (если это сломано — всё остальное бессмысленно)
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0xFF] == 0x16
assert INV_SBOX[SBOX[42]] == 42


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    """Умножение в GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# --------------------------------------------------------------------------
# Развёртывание ключа
# --------------------------------------------------------------------------

def expand_key(key: bytes) -> Tuple[Tuple[Tuple[int, int, int, int], ...], int]:
    """Возвращает (round_keys, rounds). round_keys — список из 4*(Nr+1) слов."""
    if len(key) != _KEY_SIZE:
        raise ValueError(
            "Ключ должен быть ровно 32 байта (256 бит), получено %d" % len(key)
        )
    nk = 8
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return tuple(tuple(w) for w in words), nr


# --------------------------------------------------------------------------
# Блочные операции (state — плоский список 16 байт, column-major)
# --------------------------------------------------------------------------

def _add_round_key(state, round_keys, rnd):
    base = rnd * 4
    for c in range(4):
        word = round_keys[base + c]
        for r in range(4):
            state[r + 4 * c] ^= word[r]


def _sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _inv_shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _mix_columns(state):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        state[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)


def _inv_mix_columns(state):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        state[i + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        state[i + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        state[i + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)


def encrypt_block(block: bytes, round_keys, rounds: int) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 16 байт")
    state = list(block)
    _add_round_key(state, round_keys, 0)
    for rnd in range(1, rounds):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys, rnd)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys, rounds)
    return bytes(state)


def decrypt_block(block: bytes, round_keys, rounds: int) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен быть 16 байт")
    state = list(block)
    _add_round_key(state, round_keys, rounds)
    for rnd in range(rounds - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys, rnd)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys, 0)
    return bytes(state)


# --------------------------------------------------------------------------
# Режим CBC и дополнение PKCS#7
# --------------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc_nopad(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC без дополнения; длина data должна быть кратна 16."""
    if len(data) % BLOCK_SIZE:
        raise ValueError("Длина данных должна быть кратна 16 байтам")
    round_keys, rounds = expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = _xor(data[i:i + BLOCK_SIZE], prev)
        prev = encrypt_block(block, round_keys, rounds)
        out += prev
    return bytes(out)


def decrypt_cbc_nopad(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC без снятия дополнения; длина data должна быть кратна 16."""
    if len(data) % BLOCK_SIZE:
        raise ValueError("Длина данных должна быть кратна 16 байтам")
    round_keys, rounds = expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        chunk = data[i:i + BLOCK_SIZE]
        out += _xor(decrypt_block(chunk, round_keys, rounds), prev)
        prev = chunk
    return bytes(out)


def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Данные не кратны размеру блока — это не шифртекст AES-CBC")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE:
        raise ValueError("Повреждённое дополнение PKCS#7 (неверный ключ?)")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Повреждённое дополнение PKCS#7 (неверный ключ?)")
    return data[:-n]


# --------------------------------------------------------------------------
# Быстрые бэкенды (необязательные)
# --------------------------------------------------------------------------

def _open_backend():
    """Возвращает (encrypt_fn, decrypt_fn) поверх внешней библиотеки или None."""
    try:  # cryptography
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def enc(key, iv, data):
            c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return c.update(data) + c.finalize()

        def dec(key, iv, data):
            c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return c.update(data) + c.finalize()

        return ("cryptography", enc, dec)
    except Exception:
        pass
    try:  # pycryptodome
        from Crypto.Cipher import AES as _AES

        def enc(key, iv, data):
            return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)

        def dec(key, iv, data):
            return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)

        return ("pycryptodome", enc, dec)
    except Exception:
        pass
    return None


_BACKEND = _open_backend()


def backend_name() -> str:
    """Название используемого AES-бэкенда (для отчётов и диагностики)."""
    return _BACKEND[0] if _BACKEND else "pure-python"


# --------------------------------------------------------------------------
# Высокоуровневые функции
# --------------------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, iv: bytes = b"") -> bytes:
    """AES-256-CBC + PKCS#7 (аналог `openssl enc -K <hex> -iv 00 -aes-256-cbc`)."""
    iv = _normalize_iv(iv)
    data = pad(plaintext)
    if _BACKEND:
        return _BACKEND[1](key, iv, data)
    return encrypt_cbc_nopad(key, iv, data)


def decrypt(key: bytes, ciphertext: bytes, iv: bytes = b"") -> bytes:
    """Расшифровка AES-256-CBC и снятие PKCS#7. Бросает ValueError при неверном ключе."""
    iv = _normalize_iv(iv)
    if not ciphertext:
        raise ValueError("Пустой файл")
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Размер файла не кратен 16 байтам — файл не зашифрован AES-CBC")
    if _BACKEND:
        plain = _BACKEND[2](key, iv, ciphertext)
    else:
        plain = decrypt_cbc_nopad(key, iv, ciphertext)
    return unpad(plain)


def _normalize_iv(iv: bytes) -> bytes:
    if not iv:
        return b"\x00" * BLOCK_SIZE
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) <= 32 else iv.encode("ascii", "replace")
    if len(iv) < BLOCK_SIZE:
        iv = iv + b"\x00" * (BLOCK_SIZE - len(iv))
    return bytes(iv[:BLOCK_SIZE])
