"""abluatool — утилита для расшифровки/правки/шифрования Lua-скриптов
в PC-портах Angry Birds (движок KA3D / Fusion).

Схема (по гайду Angry Birds Wiki «How to activate PC games (2024)»):
    options.lua  --(AES-256-CBC, IV=0)-->  контейнер (raw / LZMA / 7z)
                 --(распаковка)-->          Lua-байткод / исходник
                 --(правка флагов g_registrationEnabled и g_updateCheckEnabled)
                 --(упаковка + AES-256-CBC)-->  обратно в data/scripts/options.lua

Публичный API:
    from abluatool import engine, keys, aes, containers, luafmt, games
"""

__version__ = "1.0.0"
__all__ = ["aes", "containers", "engine", "games", "keys", "luafmt", "sevenzip"]
