import os
import tempfile
import unittest
from unittest.mock import patch

from ext4lib.i18n import (
    LANGUAGES,
    detect_language,
    language_from_label,
    language_label,
    load_language,
    save_language,
    tr,
)


class I18nTests(unittest.TestCase):
    def test_supported_languages(self):
        self.assertEqual(LANGUAGES["ko"], "한국어")
        self.assertEqual(LANGUAGES["en"], "English")
        self.assertEqual(LANGUAGES["ja"], "日本語")

    def test_translation_lookup(self):
        self.assertEqual(tr("en", "scan"), "Rescan disks")
        self.assertEqual(tr("ja", "write_enable"), "書き込みを許可")
        self.assertEqual(
            tr("en", "mounting", letter="E:"),
            "Mounting as drive E:…",
        )

    def test_language_label_roundtrip(self):
        for code, label in LANGUAGES.items():
            self.assertEqual(language_label(code), label)
            self.assertEqual(language_from_label(label), code)

    def test_language_setting_persists(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"LOCALAPPDATA": temp}, clear=False):
                save_language("ja")
                self.assertEqual(load_language(), "ja")
                save_language("en")
                self.assertEqual(load_language(), "en")

    def test_os_locale_detection(self):
        with patch("ext4lib.i18n.locale.getlocale", return_value=("ja_JP", "UTF-8")):
            self.assertEqual(detect_language(), "ja")
        with patch("ext4lib.i18n.locale.getlocale", return_value=("en_US", "UTF-8")):
            self.assertEqual(detect_language(), "en")
        with patch("ext4lib.i18n.locale.getlocale", return_value=("fr_FR", "UTF-8")):
            self.assertEqual(detect_language(), "ko")


if __name__ == "__main__":
    unittest.main()
