"""Сквозные проверки: расшифровка -> правка -> упаковка -> проверка -> откат."""

import os
import shutil
import tempfile
import unittest

from abluatool import aes, containers, engine, games, keys, luafmt

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as handle:
        return handle.read()


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ablua-test-")
        self.classic = keys.by_id("classic")
        self.seasons = keys.by_id("seasons")
        self.source = _fixture_bytes("options_source.lua")
        self.bytecode = _fixture_bytes("options_bytecode.luac")

        # две «установки»: 7z+текст и LZMA+байткод
        self.game_dir = os.path.join(self.tmp, "Rovio Entertainment Ltd", "Angry Birds")
        self.game_dir2 = os.path.join(self.tmp, "Rovio Entertainment Ltd", "Angry Birds Seasons")
        self.file1 = os.path.join(self.game_dir, "data", "scripts", "options.lua")
        self.file2 = os.path.join(self.game_dir2, "data", "scripts", "options.lua")
        self._write(self.file1, aes.encrypt(self.classic.key, containers.pack(self.source, containers.CONTAINER_7Z, "options.lua")))
        self._write(self.file2, aes.encrypt(self.seasons.key, containers.pack(self.bytecode, containers.CONTAINER_LZMA)))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _write(path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)

    def _read(self, path: str) -> bytes:
        with open(path, "rb") as handle:
            return handle.read()

    # ------------------------------------------------------------------
    def test_analyze_detects_game_and_container(self):
        info = engine.analyze(self.file1)
        self.assertTrue(info.ok, info.error)
        self.assertEqual(info.game.id, "classic")
        self.assertEqual(info.container, containers.CONTAINER_7Z)
        self.assertEqual(info.inner_kind, luafmt.KIND_LUA_TEXT)
        self.assertEqual(info.flags["g_registrationEnabled"], "true")

    def test_analyze_bytecode(self):
        info = engine.analyze(self.file2)
        self.assertEqual(info.game.id, "seasons")
        self.assertEqual(info.container, containers.CONTAINER_LZMA)
        self.assertEqual(info.inner_kind, luafmt.KIND_LUA_BYTECODE)

    def test_activate_text_game(self):
        before = self._read(self.file1)
        report = engine.activate(self.file1)
        self.assertEqual(report.game.id, "classic")
        self.assertTrue(report.written)
        self.assertTrue(report.verified)
        self.assertEqual(report.flags_after["g_registrationEnabled"], "false")
        self.assertTrue(os.path.exists(engine.backup_path(self.file1)))
        self.assertEqual(self._read(engine.backup_path(self.file1)), before)

        # независимая проверка: расшифровываем и смотрим содержимое
        plain = aes.decrypt(self.classic.key, self._read(self.file1))
        text = containers.unpack(plain).content
        self.assertIn(b"gamelua.g_registrationEnabled = false", text)
        self.assertIn(b"gamelua.g_updateCheckEnabled = false", text)
        self.assertIn(b"gamelua.g_soundEnabled = true", text)

    def test_activate_bytecode_game(self):
        before = self._read(self.file2)
        report = engine.activate(self.file2)
        self.assertTrue(report.verified)
        self.assertEqual(report.flags_after["g_updateCheckEnabled"], "false")
        plain = aes.decrypt(self.seasons.key, self._read(self.file2))
        unpacked = containers.unpack(plain)
        self.assertEqual(luafmt.detect_kind(unpacked.content), luafmt.KIND_LUA_BYTECODE)
        state = luafmt.flags_state(unpacked.content)
        self.assertEqual(state["g_registrationEnabled"], "false")
        self.assertNotEqual(self._read(self.file2), before)

    def test_activate_twice_is_noop(self):
        engine.activate(self.file1)
        snapshot = self._read(self.file1)
        report = engine.activate(self.file1)
        self.assertFalse(report.changed)
        self.assertFalse(report.written)
        self.assertEqual(self._read(self.file1), snapshot)

    def test_dry_run_does_not_write(self):
        before = self._read(self.file1)
        report = engine.activate(self.file1, dry_run=True)
        self.assertTrue(report.changed)
        self.assertFalse(report.written)
        self.assertEqual(self._read(self.file1), before)
        self.assertFalse(os.path.exists(engine.backup_path(self.file1)))

    def test_restore_returns_original(self):
        before = self._read(self.file1)
        engine.activate(self.file1)
        report = engine.restore(self.file1)
        self.assertTrue(report.written)
        self.assertEqual(self._read(self.file1), before)

    def test_restore_without_backup_fails(self):
        with self.assertRaises(engine.EngineError):
            engine.restore(self.file2)

    def test_no_backup_option(self):
        engine.activate(self.file1, backup=False)
        self.assertFalse(os.path.exists(engine.backup_path(self.file1)))

    def test_wrong_key_message(self):
        """Файл, зашифрованный неизвестным ключом, должен быть отвергнут.

        Шифртекст подбираем так, чтобы ни один известный ключ не давал
        правдоподобного результата (иначе тест был бы вероятностным:
        неверный ключ с шансом ~1/256 даёт корректное дополнение PKCS#7).
        """
        import itertools

        unknown_key = b"UnknownKey-000000000000000000000"  # ровно 32 байта
        plain = b"not a real options.lua at all" * 8
        broken = os.path.join(self.tmp, "broken.lua")
        for extra in itertools.count():
            blob = aes.encrypt(unknown_key, plain + b" " * extra)
            if all(self._rejected(blob, game, key) for game, key in keys.all_keys()):
                self._write(broken, blob)
                break
        with self.assertRaises(engine.KeyNotFound):
            engine.activate(broken)

    @staticmethod
    def _rejected(blob: bytes, game, key: bytes) -> bool:
        try:
            decrypted = aes.decrypt(key, blob)
        except ValueError:
            return True
        return engine.payload_score(decrypted) <= 0

    def test_explicit_key(self):
        report = engine.activate(self.file1, key=self.classic.key)
        self.assertEqual(report.key, self.classic.key)

    def test_explicit_game(self):
        report = engine.analyze(self.file2, game=self.seasons)
        self.assertEqual(report.game.id, "seasons")

    def test_key_guessing_prefers_folder_name(self):
        """Для папки Seasons первым ключом должен проверяться ключ Seasons."""
        candidates = engine._candidate_keys(self.file2)
        self.assertEqual(candidates[0][0].id, "seasons")

    def test_find_options_files(self):
        found = engine.find_options_files(os.path.join(self.tmp, "Rovio Entertainment Ltd"))
        self.assertEqual(len(found), 2)

    def test_games_scan(self):
        found = games.find_games([os.path.join(self.tmp, "Rovio Entertainment Ltd")])
        self.assertEqual(len(found), 2)
        titles = {item.game.id for item in found if item.game}
        self.assertEqual(titles, {"classic", "seasons"})

    def test_decrypt_and_encrypt_roundtrip(self):
        out = os.path.join(self.tmp, "decrypted.lua")
        engine.decrypt_file(self.file1, out_path=out)
        self.assertEqual(self._read(out), self.source)

        back = os.path.join(self.tmp, "reencrypted.lua")
        engine.encrypt_file(out, back, key=self.classic.key, container=containers.CONTAINER_7Z)
        plain = aes.decrypt(self.classic.key, self._read(back))
        self.assertEqual(containers.unpack(plain).content, self.source)

    def test_plaintext_file_is_analyzed(self):
        """Уже расшифрованный файл тоже должен разбираться."""
        path = os.path.join(self.game_dir, "data", "scripts", "options_open.lua")
        self._write(path, self.source)
        info = engine.analyze(path)
        self.assertTrue(info.ok, info.error)
        self.assertIsNone(info.key)
        self.assertEqual(info.flags["g_registrationEnabled"], "true")
        self.assertIn("не зашифрован", " ".join(info.notes))

    def test_plaintext_file_activated_and_encrypted(self):
        """Расшифрованный файл активируется и снова шифруется ключом игры."""
        path = os.path.join(self.game_dir, "data", "scripts", "options_open.lua")
        self._write(path, self.source)
        report = engine.activate(path)  # игра угадывается по пути
        self.assertEqual(report.game.id, "classic")
        self.assertTrue(report.written)
        data = self._read(path)
        text = containers.unpack(aes.decrypt(self.classic.key, data)).content
        self.assertIn(b"g_registrationEnabled = false", text)

    def test_key_from_text(self):
        self.assertEqual(keys.key_from_text(self.classic.key.decode()), self.classic.key)
        self.assertEqual(keys.key_from_text(self.classic.key.hex()), self.classic.key)
        with self.assertRaises(ValueError):
            keys.key_from_text("короткий")


if __name__ == "__main__":
    unittest.main()
