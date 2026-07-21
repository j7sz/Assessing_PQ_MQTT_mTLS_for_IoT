#!/usr/bin/env python3
"""Regression tests for non-overlapping linked heap reporting."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "extract_firmware_resources", ROOT / "tools/extract_firmware_resources.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class HeapCapacityTests(unittest.TestCase):
    def test_caps_heap_at_stack_bottom(self):
        symbols = {
            "__heap_start": 0x20003800,
            "__heap_end": 0x20080000,
            "__StackBottom": 0x20049000,
        }
        self.assertEqual(
            MODULE.usable_heap_capacity(symbols), 0x20049000 - 0x20003800
        )

    def test_uses_heap_end_when_stack_is_in_scratch_bank(self):
        symbols = {
            "__heap_start": 0x20003800,
            "__heap_end": 0x20040000,
            "__StackBottom": 0x20041000,
        }
        self.assertEqual(
            MODULE.usable_heap_capacity(symbols), 0x20040000 - 0x20003800
        )


if __name__ == "__main__":
    unittest.main()
