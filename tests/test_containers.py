"""Проверка контейнеров: 7z (свой разбор и своя сборка), LZMA, «как есть»."""

import lzma
import unittest

from abluatool import containers, sevenzip

PAYLOAD = (
    b"-- options.lua\n"
    b"gamelua = {}\n"
    b"gamelua.g_registrationEnabled = true\n"
    b"gamelua.g_updateCheckEnabled = true\n" * 20
)


class TestContainers(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(containers.detect(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 40), containers.CONTAINER_7Z)
        self.assertEqual(containers.detect(containers.LZMA_MAGIC + b"\x00" * 20), containers.CONTAINER_LZMA)
        self.assertEqual(containers.detect(b"\x1bLua" + b"\x00" * 20), containers.CONTAINER_RAW)

    def test_raw_roundtrip(self):
        packed = containers.pack(PAYLOAD, containers.CONTAINER_RAW)
        self.assertEqual(packed, PAYLOAD)
        unpacked = containers.unpack(packed)
        self.assertEqual(unpacked.content, PAYLOAD)
        self.assertEqual(unpacked.container, containers.CONTAINER_RAW)

    def test_lzma_roundtrip(self):
        packed = containers.pack(PAYLOAD, containers.CONTAINER_LZMA)
        self.assertTrue(packed.startswith(containers.LZMA_MAGIC))
        unpacked = containers.unpack(packed)
        self.assertEqual(unpacked.content, PAYLOAD)
        self.assertEqual(unpacked.container, containers.CONTAINER_LZMA)
        # совместимость со «сырым» LZMA-потоком (как делает lzma.exe из SDK)
        self.assertEqual(
            lzma.decompress(packed[9:], format=lzma.FORMAT_ALONE), PAYLOAD
        )

    def test_7z_roundtrip(self):
        packed = containers.pack(PAYLOAD, containers.CONTAINER_7Z, "options.lua")
        self.assertTrue(packed.startswith(b"7z"))
        unpacked = containers.unpack(packed)
        self.assertEqual(unpacked.content, PAYLOAD)
        self.assertEqual(unpacked.name, "options.lua")
        self.assertEqual(unpacked.container, containers.CONTAINER_7Z)

    def test_7z_keeps_name(self):
        packed = containers.pack(PAYLOAD, containers.CONTAINER_7Z, r"data\scripts\options.lua")
        unpacked = containers.unpack(packed)
        self.assertEqual(unpacked.name, "options.lua")

    def test_7z_picks_options_file(self):
        first = sevenzip.create_archive("aaa.txt", b"x" * 100)
        self.assertEqual(sevenzip.read_archive(first)[0].name, "aaa.txt")

    def test_broken_lzma(self):
        with self.assertRaises(containers.ContainerError):
            containers.unpack(containers.LZMA_MAGIC + b"\x00\x01\x02\x03")


class TestSevenZip(unittest.TestCase):
    def test_is_7z(self):
        self.assertTrue(sevenzip.is_7z(b"7z\xbc\xaf\x27\x1c"))
        self.assertTrue(sevenzip.is_7z(b"7z\x00\x00"))
        self.assertFalse(sevenzip.is_7z(b"LZMA"))

    def test_header_is_valid_7z(self):
        blob = sevenzip.create_archive("options.lua", PAYLOAD)
        entries = sevenzip.read_archive(blob)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].data, PAYLOAD)

    def test_large_payload(self):
        data = bytes(range(256)) * 400  # 100 КБ
        blob = sevenzip.create_archive("big.lua", data)
        self.assertEqual(sevenzip.read_archive(blob)[0].data, data)

    def test_empty_payload(self):
        blob = sevenzip.create_archive("empty.lua", b"")
        entries = sevenzip.read_archive(blob)
        self.assertEqual(entries[0].data, b"")

    def test_py7zr_can_read_our_archive(self):
        py7zr = _py7zr()
        if py7zr is None:
            self.skipTest("py7zr не установлен")
        import os
        import tempfile

        blob = sevenzip.create_archive("options.lua", PAYLOAD)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.7z")
            with open(path, "wb") as handle:
                handle.write(blob)
            with py7zr.SevenZipFile(path) as archive:
                self.assertEqual(archive.getnames(), ["options.lua"])
            out = os.path.join(tmp, "out")
            with py7zr.SevenZipFile(path) as archive:
                archive.extractall(out)
            with open(os.path.join(out, "options.lua"), "rb") as handle:
                self.assertEqual(handle.read(), PAYLOAD)

    def test_read_py7zr_archive(self):
        py7zr = _py7zr()
        if py7zr is None:
            self.skipTest("py7zr не установлен")
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.7z")
            # по умолчанию py7zr пишет сжатый заголовок и цепочку BCJ+LZMA2
            with py7zr.SevenZipFile(path, "w") as archive:
                archive.writestr(PAYLOAD, "data/options.lua")
                archive.writestr(b"z" * 1000, "data/other.lua")
            with open(path, "rb") as handle:
                blob = handle.read()
        entries = {e.name: e.data for e in sevenzip.read_archive(blob)}
        self.assertEqual(entries["data/options.lua"], PAYLOAD)
        self.assertEqual(entries["data/other.lua"], b"z" * 1000)


def _py7zr():
    try:
        import py7zr  # type: ignore

        return py7zr
    except Exception:
        return None


if __name__ == "__main__":
    unittest.main()
