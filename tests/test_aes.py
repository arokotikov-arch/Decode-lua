"""Проверка AES-256-CBC: векторы NIST и сверка с openssl."""

import os
import shutil
import subprocess
import tempfile
import unittest

from abluatool import aes

# NIST SP 800-38A, F.2.5 / F.2.6 (AES-256-CBC)
NIST_KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PLAIN = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST_CIPHER = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)


class TestAes(unittest.TestCase):
    def test_nist_vector_encrypt(self):
        self.assertEqual(aes.encrypt_cbc_nopad(NIST_KEY, NIST_IV, NIST_PLAIN), NIST_CIPHER)

    def test_nist_vector_decrypt(self):
        self.assertEqual(aes.decrypt_cbc_nopad(NIST_KEY, NIST_IV, NIST_CIPHER), NIST_PLAIN)

    def test_padding_roundtrip(self):
        for length in (0, 1, 15, 16, 17, 100, 1000):
            data = bytes(range(256))[:length] or b""
            data = (b"AngryBirds" * 200)[:length]
            key = bytes(range(32))
            secret = aes.encrypt(key, data)
            self.assertEqual(len(secret) % 16, 0)
            self.assertEqual(aes.decrypt(key, secret), data)

    def test_wrong_key_detected(self):
        """Неверный ключ почти всегда ловится по дополнению PKCS#7.

        Вероятность случайного «правильного» дополнения около 1/256, поэтому
        ключ подбираем в тесте: нам нужен именно тот, что даёт ошибку.
        """
        secret = aes.encrypt(b"A" * 32, b"secret data" * 4)
        for candidate in range(1, 256):
            wrong = bytes([candidate]) * 32
            try:
                aes.decrypt(wrong, secret)
            except ValueError as exc:
                self.assertIn("дополнение", str(exc))
                return
        self.fail("ни один из 255 неверных ключей не был отвергнут")

    def test_game_key_is_ascii_32(self):
        self.assertEqual(len(b"USCaPQpA4TSNVxMI1v9SK9UC0yZuAnb2"), 32)

    @unittest.skipUnless(shutil.which("openssl"), "openssl не найден")
    def test_matches_openssl(self):
        key = b"USCaPQpA4TSNVxMI1v9SK9UC0yZuAnb2"
        data = b"-- options.lua\n" + b"gamelua.g_soundEnabled = true\n" * 5
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.bin")
            dst = os.path.join(tmp, "out.bin")
            with open(src, "wb") as handle:
                handle.write(data)
            subprocess.run(
                [
                    "openssl", "enc", "-K", key.hex(), "-iv", "00", "-aes-256-cbc",
                    "-in", src, "-out", dst,
                ],
                check=True,
                capture_output=True,
            )
            with open(dst, "rb") as handle:
                openssl_result = handle.read()
        self.assertEqual(aes.encrypt(key, data), openssl_result)
        self.assertEqual(aes.decrypt(key, openssl_result), data)


if __name__ == "__main__":
    unittest.main()
