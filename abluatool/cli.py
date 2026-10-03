"""Командная строка: scan / info / decrypt / encode / activate / restore / gui.

Все сообщения — по-русски, потому что инструмент рассчитан на игроков,
а не на разработчиков.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__, containers, engine, games, keys, luafmt

__all__ = ["main", "build_parser"]

GUIDE_URL = (
    "https://angrybirds.fandom.com/wiki/"
    "User_blog:ChickenLover21/How_to_activate_PC_games_(2024)"
)
SITE_URL = "https://web.archive.org/web/20131217034005/download.angrybirds.com"


# --------------------------------------------------------------------------
# Оформление вывода
# --------------------------------------------------------------------------

class _Colors:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)


#: Текущая палитра (обновляется в main, чтобы функции-помощники тоже её видели)
_COLORS = _Colors(False)


def _enable_ansi() -> bool:
    """Включить ANSI-цвета в консоли Windows и вернуть признак поддержки."""
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:  # pragma: no cover - только Windows
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False


def _print(text: str = "") -> None:
    try:
        print(text)
    except UnicodeEncodeError:  # консоль с однобайтовой кодировкой
        sys.stdout.buffer.write(text.encode("utf-8", "replace") + b"\n")


# --------------------------------------------------------------------------
# Разбор аргументов
# --------------------------------------------------------------------------

def _add_common(parser: argparse.ArgumentParser, suppress: bool = True) -> None:
    """Общие параметры: их можно указывать и до команды, и после неё."""
    default = argparse.SUPPRESS if suppress else None
    flag_default = argparse.SUPPRESS if suppress else False
    parser.add_argument("--key", default=default, help="свой ключ (32 символа или 64 hex-цифры)")
    parser.add_argument(
        "--game",
        default=default,
        help="идентификатор игры: " + ", ".join(g.id for g in keys.GAMES),
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        default=flag_default,
        help="не создавать резервную копию *.ablua.bak",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=flag_default,
        help="только показать, что будет сделано",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ablua",
        description=(
            "Активатор PC-версий Angry Birds: снимает шифрование с options.lua, "
            "выключает регистрацию и проверку обновлений, упаковывает файл обратно."
        ),
        epilog="Проект не связан с Rovio. Гайд-первоисточник: %s" % GUIDE_URL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="ablua %s" % __version__)
    _add_common(parser, suppress=False)

    sub = parser.add_subparsers(dest="command", metavar="КОМАНДА")

    p_scan = sub.add_parser("scan", help="найти установленные игры")
    _add_common(p_scan)
    p_scan.add_argument("--root", action="append", help="каталог для поиска (можно несколько раз)")

    p_info = sub.add_parser("info", help="показать состояние файла игры")
    _add_common(p_info)
    p_info.add_argument("file", help="путь к data/scripts/options.lua")

    p_dec = sub.add_parser("decrypt", help="расшифровать файл (и распаковать контейнер)")
    _add_common(p_dec)
    p_dec.add_argument("file")
    p_dec.add_argument("-o", "--out", help="куда сохранить результат")
    p_dec.add_argument("--no-unpack", action="store_true", help="не распаковывать контейнер (7z/LZMA)")

    p_enc = sub.add_parser("encode", help="зашифровать подготовленный файл")
    _add_common(p_enc)
    p_enc.add_argument("file")
    p_enc.add_argument("-o", "--out", required=True)
    p_enc.add_argument(
        "--container",
        choices=[containers.CONTAINER_7Z, containers.CONTAINER_LZMA, containers.CONTAINER_RAW],
        default=containers.CONTAINER_RAW,
        help="во что упаковать перед шифрованием (по умолчанию как есть)",
    )

    p_act = sub.add_parser("activate", help="активировать игру (файл или папка установки)")
    _add_common(p_act)
    p_act.add_argument("path", nargs="?", help="папка игры или путь к options.lua (по умолчанию — найти самому)")
    p_act.add_argument("--root", action="append", help="где искать игру, если путь не указан")
    p_act.add_argument("--all", action="store_true", help="обработать все найденные игры")
    p_act.add_argument("--force", action="store_true", help="писать файл, даже если менять нечего")

    p_res = sub.add_parser("restore", help="вернуть исходный файл из резервной копии")
    p_res.add_argument("file")

    p_gui = sub.add_parser("gui", help="открыть графический интерфейс в браузере")
    p_gui.add_argument("--port", type=int, default=8765, help="порт (по умолчанию 8765)")
    p_gui.add_argument("--host", default="127.0.0.1", help="адрес прослушивания")
    p_gui.add_argument("--root", help="каталог, внутри которого разрешено работать")
    p_gui.add_argument("--no-browser", action="store_true", help="не открывать браузер автоматически")

    sub.add_parser("wizard", help="пошаговый режим с вопросами (для двойного клика)")
    return parser


def _resolve_game(args) -> Optional[keys.Game]:
    if not args.game:
        return None
    game = keys.by_id(args.game)
    if game is None:
        raise SystemExit(
            "Неизвестная игра: %s. Доступные: %s"
            % (args.game, ", ".join(g.id for g in keys.GAMES))
        )
    return game


def _resolve_key(args) -> Optional[bytes]:
    if not args.key:
        return None
    try:
        return keys.key_from_text(args.key)
    except ValueError as exc:
        raise SystemExit(str(exc))


# --------------------------------------------------------------------------
# Команды
# --------------------------------------------------------------------------

def cmd_scan(args, colors: _Colors) -> int:
    roots = args.root
    found = games.find_games(roots)
    if not found:
        _print(colors.yellow("Игры не найдены."))
        _print()
        _print("Что можно сделать:")
        _print("  1) указать папку вручную:  ablua scan --root \"D:\\Games\"")
        _print("  2) указать файл напрямую:  ablua info \"C:\\...\\Angry Birds\\data\\scripts\\options.lua\"")
        _print("  3) если игра ещё не установлена — дистрибутивы сохранились в веб-архиве:")
        _print("     %s" % SITE_URL)
        return 1

    _print(colors.bold("Найдено установок: %d" % len(found)))
    problems = 0
    for item in found:
        _print("")
        _print(colors.bold(item.title))
        _print("  Папка: %s" % item.path)
        if not item.options_files:
            _print(colors.yellow("  options.lua не найден — возможно, игра ещё не запускалась"))
            problems += 1
            continue
        for file in item.options_files:
            info = engine.analyze(file, key=_resolve_key(args), game=_resolve_game(args))
            if not info.ok:
                _print(colors.red("  %s: %s" % (file, info.error)))
                problems += 1
                continue
            state = ", ".join("%s=%s" % (k, v) for k, v in sorted(info.flags.items())) or "флаги не найдены"
            _print("  Файл:  %s" % file)
            _print("  Игра:  %s | %s | %s" % (
                info.game.title if info.game else "?",
                containers.container_title(info.container),
                luafmt.kind_title(info.inner_kind),
            ))
            _print("  Флаги: %s" % state)
            already = all(value == "false" for value in info.flags.values()) and info.flags
            if already:
                _print(colors.green("  Уже активировано ✔"))
            else:
                _print(colors.yellow("  Требуется активация → ablua activate \"%s\"" % item.path))
    return 1 if problems else 0


def cmd_info(args, colors: _Colors) -> int:
    info = engine.analyze(args.file, key=_resolve_key(args), game=_resolve_game(args))
    _print(info.to_text())
    return 0 if info.ok else 2


def cmd_decrypt(args, colors: _Colors) -> int:
    report = engine.decrypt_file(
        args.file,
        out_path=args.out,
        key=_resolve_key(args),
        game=_resolve_game(args),
        unpack=not args.no_unpack,
    )
    _print(report.to_text())
    if report.out_path and os.path.exists(report.out_path):
        size = os.path.getsize(report.out_path)
        _print()
        _print("Сохранено %d байт в %s" % (size, report.out_path))
    return 0


def cmd_encode(args, colors: _Colors) -> int:
    report = engine.encrypt_file(
        args.file,
        out_path=args.out,
        key=_resolve_key(args),
        game=_resolve_game(args),
        container=args.container,
    )
    _print(report.to_text())
    _print()
    _print(colors.yellow("Не забудьте положить файл на место: data/scripts/options.lua"))
    return 0


def _gather_targets(args) -> List[str]:
    path = args.path
    if path:
        if os.path.isdir(path):
            files = engine.find_options_files(path)
            if not files:
                raise SystemExit("В папке %s не найдено data/scripts/options.lua" % path)
            return files
        return [path]
    found = games.find_games(args.root)
    targets: List[str] = []
    for item in found:
        targets.extend(item.options_files)
    return targets


def cmd_activate(args, colors: _Colors) -> int:
    try:
        targets = _gather_targets(args)
    except SystemExit:
        raise
    if not targets:
        _print(colors.red("Не найдено ни одной игры."))
        _print("Укажите папку установки: ablua activate \"C:\\Program Files (x86)\\Rovio Entertainment Ltd\\Angry Birds\"")
        return 1
    if len(targets) > 1 and not args.all:
        _print("Найдено несколько игр:")
        for index, target in enumerate(targets, 1):
            _print("  %d) %s" % (index, target))
        _print()
        _print("Запустите с ключом --all, чтобы обработать все сразу.")
        return 1

    failures = 0
    for target in targets:
        _print("")
        try:
            report = engine.activate(
                target,
                key=_resolve_key(args),
                game=_resolve_game(args),
                backup=not args.no_backup,
                dry_run=args.dry_run,
            )
            report.game = report.game or keys.by_folder_name(target)
            _print(report.to_text())
            if report.written:
                _print(colors.green("Готово! Запускайте игру."))
            elif not report.changes:
                _print(colors.green("Файл уже активирован — ничего менять не потребовалось."))
        except engine.EngineError as exc:
            failures += 1
            _print(colors.red("Ошибка: %s" % exc))
        except Exception as exc:  # неожиданное — но не молча
            failures += 1
            _print(colors.red("Непредвиденная ошибка: %s: %s" % (type(exc).__name__, exc)))
    return 1 if failures else 0


def cmd_restore(args, colors: _Colors) -> int:
    try:
        report = engine.restore(args.file)
    except engine.EngineError as exc:
        _print(colors.red(str(exc)))
        return 1
    _print(report.to_text())
    return 0


def cmd_gui(args, colors: _Colors) -> int:
    from . import webui

    return webui.run(
        host=args.host,
        port=args.port,
        root=args.root,
        open_browser=not args.no_browser,
    )


# --------------------------------------------------------------------------
# Пошаговый режим
# --------------------------------------------------------------------------

def cmd_wizard(args, colors: _Colors) -> int:
    _print(colors.bold("=== Активатор PC-версий Angry Birds ==="))
    _print("Выключим регистрацию и проверку обновлений в options.lua.")
    _print("Файл будет изменён на месте, рядом останется копия *.ablua.bak —")
    _print("её можно вернуть командой restore.")
    _print()

    found = games.find_games()
    targets: List[str] = []
    if found:
        _print("Найдены игры:")
        for index, item in enumerate(found, 1):
            mark = "" if item.options_files else "  (options.lua не найден)"
            _print("  %d) %s%s" % (index, item.title, mark))
        _print("  0) указать путь вручную")
        choice = _ask("Выберите номер (Enter — активировать всё найденное): ")
        if choice.strip() in ("", None):
            for item in found:
                targets.extend(item.options_files)
        elif choice.strip() == "0":
            targets = _ask_path()
        else:
            try:
                targets = found[int(choice) - 1].options_files
            except (ValueError, IndexError):
                _print(colors.red("Непонятный выбор."))
                return 1
    else:
        _print("Автоматически игры не найдены.")
        targets = _ask_path()

    if not targets:
        _print(colors.red("Нечего активировать."))
        return 1

    _print()
    _print("Будут обработаны файлы:")
    for target in targets:
        _print("  %s" % target)
    if _ask("Продолжить? [Y/n]: ").strip().lower() in ("n", "н", "no", "нет"):
        _print("Отменено.")
        return 1

    failures = 0
    for target in targets:
        _print("")
        try:
            report = engine.activate(target, backup=True)
            _print(report.to_text())
        except engine.EngineError as exc:
            failures += 1
            _print(colors.red("Ошибка: %s" % exc))
    _print()
    if failures:
        _print(colors.red("Завершено с ошибками: %d" % failures))
    else:
        _print(colors.green("Все файлы активированы. Приятной игры!"))
    _pause()
    return 1 if failures else 0


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def _ask_path() -> List[str]:
    path = _ask("Укажите папку игры или файл options.lua: ").strip().strip('"')
    if not path:
        return []
    if os.path.isdir(path):
        files = engine.find_options_files(path)
        if not files:
            _print(_COLORS.red("В этой папке нет data/scripts/options.lua"))
        return files
    if os.path.exists(path):
        return [path]
    _print(_COLORS.red("Путь не найден: %s" % path))
    return []


def _pause() -> None:
    if sys.stdin is not None and sys.stdin.isatty() and os.name == "nt":
        _ask("\nНажмите Enter, чтобы закрыть окно... ")


# --------------------------------------------------------------------------
# Точка входа
# --------------------------------------------------------------------------

COMMANDS = {
    "scan": cmd_scan,
    "info": cmd_info,
    "decrypt": cmd_decrypt,
    "encode": cmd_encode,
    "activate": cmd_activate,
    "restore": cmd_restore,
    "gui": cmd_gui,
    "wizard": cmd_wizard,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        if sys.stdin is not None and sys.stdin.isatty():
            argv = ["wizard"]
        else:
            build_parser().print_help()
            return 0

    parser = build_parser()
    args = parser.parse_args(argv)
    global _COLORS
    _COLORS = _Colors(_enable_ansi())
    colors = _COLORS

    if args.key:
        _print(colors.yellow("Используется ключ из параметров командной строки."))

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return handler(args, colors)
    except KeyboardInterrupt:
        _print("\nПрервано пользователем.")
        return 130
    except engine.EngineError as exc:
        _print(colors.red(str(exc)))
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
