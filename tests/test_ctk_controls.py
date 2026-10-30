"""Focus decoration supports native no-event callbacks and closing widgets."""
import unittest
from types import SimpleNamespace
from tkinter import TclError
from unittest import mock

from ui.ctk_controls import _focus_border


class FocusBorderTest(unittest.TestCase):
    def setUp(self):
        self.handlers = {}
        self.widget = mock.Mock()
        self.widget.winfo_exists.return_value = True
        self.widget.bind.side_effect = lambda event, handler, **_: self.handlers.update({event: handler})
        self.theme = SimpleNamespace(accent=("light-accent", "dark-accent"))
        self.border = ("light-border", "dark-border")
        self.assertIs(_focus_border(self.widget, self.theme, self.border), self.widget)

    def test_event_and_no_event_callbacks_apply_the_same_focus_colors(self):
        for arguments in ((), (SimpleNamespace(widget=self.widget),)):
            with self.subTest(arguments=len(arguments)):
                self.handlers["<FocusIn>"](*arguments)
                self.widget.configure.assert_called_with(border_color=self.theme.accent)
                self.handlers["<FocusOut>"](*arguments)
                self.widget.configure.assert_called_with(border_color=self.border)
        self.assertEqual(self.widget.bind.call_args_list[0].kwargs, {"add": "+"})
        self.assertEqual(self.widget.bind.call_args_list[1].kwargs, {"add": "+"})

    def test_late_focus_callback_does_not_configure_a_destroyed_widget(self):
        self.widget.winfo_exists.return_value = False
        self.handlers["<FocusIn>"]()
        self.handlers["<FocusOut>"]()
        self.widget.configure.assert_not_called()

    def test_native_teardown_race_is_tolerated_without_hiding_other_failures(self):
        self.widget.configure.side_effect = TclError("Synthetic Entry already destroyed")
        self.handlers["<FocusOut>"]()
        self.widget.configure.side_effect = RuntimeError("Synthetic programming error")
        with self.assertRaises(RuntimeError):
            self.handlers["<FocusIn>"]()


if __name__ == "__main__":
    unittest.main()
