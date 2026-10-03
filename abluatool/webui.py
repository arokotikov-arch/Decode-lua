"""Локальный веб-интерфейс инструмента (только стандартная библиотека).

Запуск::

    python ablua.py gui

Открывается браузер на 127.0.0.1, и вся работа (поиск игр, активация,
просмотр расшифрованного файла, откат) делается мышкой.

Безопасность: по умолчанию сервер слушает только localhost и работает
исключительно внутри каталога ``--root`` (по умолчанию — текущий каталог).
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__, containers, engine, games, luafmt

__all__ = ["run", "create_server", "Handler"]

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
INDEX_FILE = os.path.join(WEB_DIR, "index.html")


class _State:
    """Общее состояние сервера."""

    def __init__(self, root: str, allow_any_path: bool = False) -> None:
        self.root = os.path.abspath(root)
        self.allow_any_path = allow_any_path
        self.lock = threading.Lock()

    def resolve(self, path: str) -> str:
        """Привести путь к абсолютному и проверить, что он внутри корня."""
        if not path:
            raise ValueError("Пустой путь")
        absolute = os.path.abspath(os.path.expanduser(path))
        if self.allow_any_path:
            return absolute
        root = self.root.rstrip(os.sep)
        if absolute != root and not absolute.startswith(root + os.sep):
            raise ValueError(
                "Путь вне рабочего каталога (%s). Запустите с --root, чтобы расширить доступ."
                % self.root
            )
        return absolute


def _file_state(path: str) -> Dict[str, Any]:
    """Краткая информация о файле для интерфейса."""
    item: Dict[str, Any] = {
        "path": path,
        "name": os.path.basename(path),
        "exists": os.path.exists(path),
        "has_backup": engine.has_backup(path),
    }
    if not item["exists"]:
        item["error"] = "файл не найден"
        return item
    item["size"] = os.path.getsize(path)
    try:
        info = engine.analyze(path)
    except Exception as exc:  # pragma: no cover - защита от неожиданностей
        item["error"] = "%s: %s" % (type(exc).__name__, exc)
        return item
    item.update(
        {
            "game": info.game.title if info.game else None,
            "game_id": info.game.id if info.game else None,
            "container": containers.container_title(info.container),
            "container_id": info.container,
            "kind": luafmt.kind_title(info.inner_kind),
            "kind_id": info.inner_kind,
            "flags": info.flags,
            "active": bool(info.flags)
            and all(value == "false" for value in info.flags.values()),
            "error": info.error,
        }
    )
    return item


def _scan(root: str) -> Dict[str, Any]:
    """Найти игры: сначала в рабочем каталоге, потом в стандартных местах."""
    found = games.find_games([root])
    if not found:
        found = games.find_games()
    result: List[Dict[str, Any]] = []
    for item in found:
        entry = {
            "title": item.title,
            "path": item.path,
            "game_id": item.game.id if item.game else None,
            "files": [_file_state(path) for path in item.options_files],
        }
        result.append(entry)
    return {"games": result, "root": root}


def _report_dict(report: engine.Report) -> Dict[str, Any]:
    return {
        "action": report.action,
        "path": report.path,
        "written": report.written,
        "verified": report.verified,
        "dry_run": report.dry_run,
        "game": report.game.title if report.game else None,
        "container": containers.container_title(report.container),
        "kind": luafmt.kind_title(report.inner_kind),
        "backup": report.backup,
        "changes": [str(change) for change in report.changes],
        "flags_before": report.flags_before,
        "flags_after": report.flags_after,
        "notes": report.notes,
        "text": report.to_text(),
    }


class Handler(BaseHTTPRequestHandler):
    """HTTP-обработчик интерфейса."""

    state: _State  # подставляется в create_server
    server_version = "ablua/%s" % __version__

    # ------------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # тише в консоли
        pass

    # ------------------------------------------------------------------
    def _json(self, payload: Dict[str, Any], code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, code: int = 400) -> None:
        self._json({"ok": False, "error": message}, code)

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _index(self) -> None:
        try:
            with open(INDEX_FILE, "rb") as handle:
                body = handle.read()
        except OSError:
            self._error("Файл интерфейса не найден: %s" % INDEX_FILE, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - требование http.server
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)
        try:
            if route == "/":
                self._index()
            elif route == "/api/state":
                state = _scan(self.state.root)
                state["ok"] = True
                state["version"] = __version__
                state["paths"] = {
                    "root": self.state.root,
                    "guide": "https://angrybirds.fandom.com/wiki/User_blog:ChickenLover21/How_to_activate_PC_games_(2024)",
                    "download": "https://web.archive.org/web/20131217034005/download.angrybirds.com",
                }
                self._json(state)
            elif route == "/api/list":
                path = self.state.resolve(params.get("path", [self.state.root])[0])
                self._json({"ok": True, "listing": self._listing(path)})
            else:
                self._error("Неизвестный адрес: %s" % route, 404)
        except Exception as exc:
            self._error("%s: %s" % (type(exc).__name__, exc))

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path.rstrip("/") or "/"
        data = self._body()
        try:
            if route == "/api/analyze":
                self._analyze(data)
            elif route == "/api/activate":
                self._activate(data)
            elif route == "/api/activate_all":
                self._activate_all(data)
            elif route == "/api/restore":
                self._restore(data)
            elif route == "/api/save":
                self._save(data)
            elif route == "/api/decrypt":
                self._decrypt(data)
            else:
                self._error("Неизвестный адрес: %s" % route, 404)
        except engine.EngineError as exc:
            self._error(str(exc))
        except ValueError as exc:
            self._error(str(exc))
        except Exception as exc:
            self._error("%s: %s" % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    def _listing(self, path: str) -> Dict[str, Any]:
        if not os.path.isdir(path):
            raise ValueError("Это не каталог: %s" % path)
        dirs: List[str] = []
        files: List[Dict[str, Any]] = []
        try:
            for name in sorted(os.listdir(path), key=str.lower):
                full = os.path.join(path, name)
                if os.path.isdir(full):
                    dirs.append(name)
                else:
                    files.append({"name": name, "size": os.path.getsize(full)})
        except PermissionError as exc:
            raise ValueError("Нет доступа к каталогу %s (%s)" % (path, exc))
        parent = os.path.dirname(path.rstrip(os.sep))
        if not self.state.allow_any_path and not parent.startswith(self.state.root.rstrip(os.sep)):
            parent = self.state.root
        return {"path": path, "parent": parent, "dirs": dirs, "files": files[:200]}

    def _analyze(self, data: Dict[str, Any]) -> None:
        path = self.state.resolve(data.get("path", ""))
        state = _file_state(path)
        payload: Dict[str, Any] = {"ok": True, "file": state}
        if state.get("kind_id") in (luafmt.KIND_LUA_TEXT, luafmt.KIND_JSON):
            preview = self._content(path)
            payload["text"] = preview["text"]
        elif state.get("kind_id") == luafmt.KIND_LUA_BYTECODE:
            payload["note"] = (
                "Файл внутри — байткод Lua 5.1. Правка выполняется прямо в инструкциях, "
                "декодировать в текст не обязательно."
            )
        self._json(payload)

    def _content(self, path: str) -> Dict[str, Any]:
        data = open(path, "rb").read()
        _game, _key, plain, _score = engine.detect_key(data, path)
        unpacked = containers.unpack(plain)
        text: Optional[str] = None
        if luafmt.detect_kind(unpacked.content) in (luafmt.KIND_LUA_TEXT, luafmt.KIND_JSON):
            text = unpacked.content.decode("utf-8", "replace")
        return {
            "text": text,
            "container": unpacked.container,
            "kind": luafmt.detect_kind(unpacked.content),
            "size": len(unpacked.content),
        }

    def _decrypt(self, data: Dict[str, Any]) -> None:
        path = self.state.resolve(data.get("path", ""))
        info = self._content(path)
        info["ok"] = True
        info["file"] = _file_state(path)
        self._json(info)

    def _activate(self, data: Dict[str, Any]) -> None:
        path = self.state.resolve(data.get("path", ""))
        with self.state.lock:
            report = engine.activate(
                path,
                backup=bool(data.get("backup", True)),
                dry_run=bool(data.get("dry_run", False)),
            )
        payload = {"ok": True, "report": _report_dict(report), "file": _file_state(path)}
        self._json(payload)

    def _activate_all(self, data: Dict[str, Any]) -> None:
        root = self.state.resolve(data.get("root") or self.state.root)
        targets: List[str] = []
        found = games.find_games([root]) or games.find_games()
        for item in found:
            targets.extend(item.options_files)
        if not targets:
            self._error("Не найдено ни одной игры. Укажите папку вручную.")
            return
        reports = []
        with self.state.lock:
            for target in targets:
                try:
                    report = engine.activate(target, backup=True)
                    reports.append(_report_dict(report))
                except engine.EngineError as exc:
                    reports.append({"path": target, "error": str(exc)})
        self._json({"ok": True, "reports": reports, "files": [_file_state(t) for t in targets]})

    def _restore(self, data: Dict[str, Any]) -> None:
        path = self.state.resolve(data.get("path", ""))
        with self.state.lock:
            report = engine.restore(path)
        self._json({"ok": True, "report": _report_dict(report), "file": _file_state(path)})

    def _save(self, data: Dict[str, Any]) -> None:
        """Сохранить отредактированный текст: правка флагов + шифрование."""
        path = self.state.resolve(data.get("path", ""))
        text = data.get("text")
        if not isinstance(text, str):
            self._error("Не передан текст файла")
            return
        raw = open(path, "rb").read()
        game, key, plain, _score = engine.detect_key(raw, path)
        unpacked = containers.unpack(plain)

        patched = luafmt.patch(text.encode("utf-8"))
        if not patched.changed and not patched.already_off:
            self._error(
                "В тексте не найдены флаги g_registrationEnabled / g_updateCheckEnabled"
            )
            return
        name = unpacked.name or containers.guess_inner_name(path)
        repacked = containers.pack(patched.data, unpacked.container, name)
        from . import aes  # локальный импорт, чтобы не плодить циклы

        encrypted = aes.encrypt(key, repacked)
        with self.state.lock:
            import shutil

            if data.get("backup", True):
                shutil.copy2(path, engine.backup_path(path))
            engine._atomic_write(path, encrypted)
        self._json(
            {
                "ok": True,
                "changes": [str(change) for change in patched.changes],
                "file": _file_state(path),
            }
        )


def create_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    root: Optional[str] = None,
    allow_any_path: bool = False,
) -> ThreadingHTTPServer:
    """Создать (но не запускать) HTTP-сервер интерфейса."""
    state = _State(root or os.getcwd(), allow_any_path=allow_any_path)
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def run(
    host: str = "127.0.0.1",
    port: int = 8765,
    root: Optional[str] = None,
    open_browser: bool = True,
    allow_any_path: bool = False,
) -> int:
    """Запустить интерфейс и открыть браузер."""
    if not os.path.exists(INDEX_FILE):
        print("Не найден файл интерфейса: %s" % INDEX_FILE)
        return 1
    server = create_server(host=host, port=port, root=root, allow_any_path=allow_any_path)
    url_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = "http://%s:%d/" % (url_host, server.server_address[1])
    print("Интерфейс запущен: %s" % url)
    print("Рабочий каталог:   %s" % os.path.abspath(root or os.getcwd()))
    print("Остановить: Ctrl+C")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
