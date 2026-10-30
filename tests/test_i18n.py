import json
import unittest
from pathlib import Path
from unittest.mock import patch

LOCALES_DIR = Path(__file__).parents[1] / "ui" / "i18n"

# Values that are intentionally identical across locales
# (brand names, technical terms, format-only strings).
ALLOWED_UNTRANSLATED = frozenset({
    "app.name",
    "button.test_loading",
    "connectivity.cfworker_title",
    "connectivity.error_line",
    "dashboard.helper",
    "first_run.manual_mtproto",
    "language.en",
    "language.ru",
    "section.cfproxy",
    "section.cfworker",
})


def _load(code: str) -> dict:
    with open(LOCALES_DIR / f"{code}.json", encoding="utf-8") as f:
        return json.load(f)


class I18nParityTest(unittest.TestCase):
    def test_detection_does_not_require_removed_defaultlocale(self):
        from ui import i18n
        with patch.object(i18n.locale, 'getlocale', return_value=(None, None)), \
                patch.object(i18n.locale, 'getdefaultlocale', side_effect=AssertionError('deprecated API'), create=True), \
                patch.object(i18n.sys, 'platform', 'linux'), \
                patch.dict(i18n.os.environ, {'LC_ALL': '', 'LC_MESSAGES': '', 'LANG': 'ru-RU.UTF-8'}):
            self.assertEqual(i18n.detect_system_language(), i18n.LocaleEnum.russian)

    def test_en_ru_key_sets_match(self):
        en = _load("en")
        ru = _load("ru")
        self.assertEqual(
            set(en), set(ru),
            f"Missing in ru: {sorted(set(en) - set(ru))}; "
            f"missing in en: {sorted(set(ru) - set(en))}",
        )

    def test_ru_has_no_untouched_english_leftovers(self):
        en = _load("en")
        ru = _load("ru")
        leftovers = sorted(
            key for key in set(en) & set(ru)
            if en[key] == ru[key] and key not in ALLOWED_UNTRANSLATED
        )
        self.assertEqual(leftovers, [])

    def test_format_placeholders_match(self):
        import string

        en = _load("en")
        ru = _load("ru")
        for key in set(en) & set(ru):
            en_fields = {
                name for _, name, _, _ in string.Formatter().parse(en[key])
                if name
            }
            ru_fields = {
                name for _, name, _, _ in string.Formatter().parse(ru[key])
                if name
            }
            self.assertEqual(
                en_fields, ru_fields,
                f"Placeholder mismatch for key {key!r}",
            )


if __name__ == "__main__":
    unittest.main()
