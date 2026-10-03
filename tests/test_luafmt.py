"""Проверка правки флагов: текст Lua, JSON и настоящий байткод Lua 5.1."""

import os
import shutil
import subprocess
import unittest

from abluatool import luafmt

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SOURCE = os.path.join(FIXTURES, "options_source.lua")
BYTECODE = os.path.join(FIXTURES, "options_bytecode.luac")

TEXT_SAMPLE = b"""-- options
gamelua = {}
gamelua.g_registrationEnabled = true
gamelua.g_updateCheckEnabled = true
gamelua.g_soundEnabled = true
"""

JSON_SAMPLE = b'{\n  "g_registrationEnabled": true,\n  "g_updateCheckEnabled": true,\n  "g_soundEnabled": true\n}\n'


class TestTextPatch(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(luafmt.detect_kind(TEXT_SAMPLE), luafmt.KIND_LUA_TEXT)
        self.assertEqual(luafmt.detect_kind(JSON_SAMPLE), luafmt.KIND_JSON)
        self.assertEqual(luafmt.detect_kind(b"\x1bLua\x51"), luafmt.KIND_LUA_BYTECODE)
        self.assertEqual(luafmt.detect_kind(b"\x1bLJ\x01"), luafmt.KIND_LUAJIT)

    def test_patch_lua(self):
        result = luafmt.patch(TEXT_SAMPLE)
        self.assertTrue(result.changed)
        text = result.data.decode()
        self.assertIn("gamelua.g_registrationEnabled = false", text)
        self.assertIn("gamelua.g_updateCheckEnabled = false", text)
        # посторонние настройки не тронуты
        self.assertIn("gamelua.g_soundEnabled = true", text)
        self.assertEqual(result.missing, [])

    def test_patch_json(self):
        result = luafmt.patch(JSON_SAMPLE)
        self.assertIn(b'"g_registrationEnabled": false', result.data)
        self.assertIn(b'"g_soundEnabled": true', result.data)

    def test_flags_state(self):
        state = luafmt.flags_state(TEXT_SAMPLE)
        self.assertEqual(state["g_registrationEnabled"], "true")
        patched = luafmt.patch(TEXT_SAMPLE).data
        self.assertEqual(luafmt.flags_state(patched)["g_registrationEnabled"], "false")

    def test_idempotent(self):
        once = luafmt.patch(TEXT_SAMPLE).data
        twice = luafmt.patch(once)
        self.assertFalse(twice.changed)
        self.assertEqual(twice.already_off, ["g_registrationEnabled", "g_updateCheckEnabled"])

    def test_missing_flags(self):
        result = luafmt.patch(b"local a = 1\n")
        self.assertFalse(result.changed)
        self.assertEqual(sorted(result.missing), sorted(luafmt.FLAG_NAMES))

    def test_luajit_message(self):
        with self.assertRaises(luafmt.BytecodeError):
            luafmt.patch(b"\x1bLJ\x02\x00")


class TestBytecodePatch(unittest.TestCase):
    def setUp(self):
        with open(BYTECODE, "rb") as handle:
            self.data = handle.read()

    def test_fixture_is_real_bytecode(self):
        self.assertEqual(luafmt.detect_kind(self.data), luafmt.KIND_LUA_BYTECODE)

    def test_flags_before(self):
        state = luafmt.flags_state(self.data)
        self.assertEqual(state["g_registrationEnabled"], "true")
        self.assertEqual(state["g_updateCheckEnabled"], "true")

    def test_patch_flags(self):
        result = luafmt.patch(self.data)
        self.assertTrue(result.changed)
        self.assertEqual(result.missing, [])
        state = luafmt.flags_state(result.data)
        self.assertEqual(state["g_registrationEnabled"], "false")
        self.assertEqual(state["g_updateCheckEnabled"], "false")

    def test_patch_is_idempotent(self):
        once = luafmt.patch(self.data).data
        twice = luafmt.patch(once)
        self.assertFalse(twice.changed)

    def test_other_true_values_untouched(self):
        """Посторонние настройки со значением true должны остаться true.

        Проверяем на уровне инструкций: находим константу «g_soundEnabled»
        и смотрим, на какую булеву константу она всё ещё указывает.
        """
        result = luafmt.patch(self.data)
        reader, proto = luafmt._parse_chunk(result.data)
        instructions = luafmt._instructions(result.data, proto, reader.endian)
        sound_index = None
        for index, (kind, value) in enumerate(proto.constants):
            if kind == 4 and value == "g_soundEnabled":
                sound_index = index
        self.assertIsNotNone(sound_index, "в фикстуре должен быть g_soundEnabled")
        value_const = None
        for instr in instructions:
            if instr & 0x3F == luafmt.OP_SETTABLE:
                b_rk = (instr >> 23) & 0x1FF
                if (b_rk & luafmt.BITRK) and (b_rk & luafmt.MAXINDEXRK) == sound_index:
                    value_const = (instr >> 14) & luafmt.MAXINDEXRK
        self.assertIsNotNone(value_const)
        self.assertIs(
            proto.constant_value(value_const), True,
            "значение g_soundEnabled должно остаться true",
        )

    @unittest.skipUnless(shutil.which("lua") or shutil.which("lua5.1"), "нужен интерпретатор Lua 5.1")
    def test_patched_bytecode_runs(self):
        """Если в системе есть Lua 5.1 — запускаем пропатченный чанк."""
        lua = shutil.which("lua") or shutil.which("lua5.1")
        result = luafmt.patch(self.data)
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "patched.luac")
            with open(path, "wb") as handle:
                handle.write(result.data)
            script = (
                'local g = assert(loadfile("%s"))() '
                'print(g.g_registrationEnabled, g.g_updateCheckEnabled, g.g_soundEnabled)'
                % path.replace("\\", "\\\\")
            )
            proc = subprocess.run([lua, "-e", script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["false", "false", "true"])


if __name__ == "__main__":
    unittest.main()
