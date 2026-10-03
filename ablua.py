#!/usr/bin/env python3
"""Запуск инструмента активации PC-версий Angry Birds.

Примеры:

    python ablua.py                     # пошаговый режим (для двойного клика)
    python ablua.py scan                # найти установленные игры
    python ablua.py info "C:\\...\\Angry Birds\\data\\scripts\\options.lua"
    python ablua.py activate "C:\\Program Files (x86)\\Rovio Entertainment Ltd\\Angry Birds"
    python ablua.py activate --all      # активировать все найденные игры
    python ablua.py restore "C:\\...\\options.lua"
    python ablua.py gui                 # интерфейс в браузере

Подробности — в README.md.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from abluatool.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
