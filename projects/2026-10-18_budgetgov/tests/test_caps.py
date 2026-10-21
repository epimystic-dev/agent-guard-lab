from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from budgetgov import CallCap, SpendCap, TimeCap, TokenCap


class TokenCapTests(unittest.TestCase):
    def test_valid(self):
        c = TokenCap(100)
        self.assertEqual(c.limit, 100)
        self.assertEqual(c.name, "token")

    def test_rejects_non_int(self):
        with self.assertRaises(TypeError):
            TokenCap(1.5)  # type: ignore[arg-type]

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            TokenCap(-1)


class TimeCapTests(unittest.TestCase):
    def test_valid(self):
        c = TimeCap(30.0)
        self.assertEqual(c.seconds, 30.0)

    def test_int_ok(self):
        c = TimeCap(30)
        self.assertEqual(c.seconds, 30)

    def test_rejects_non_number(self):
        with self.assertRaises(TypeError):
            TimeCap("30")  # type: ignore[arg-type]

    def test_rejects_zero_or_negative(self):
        with self.assertRaises(ValueError):
            TimeCap(0)
        with self.assertRaises(ValueError):
            TimeCap(-1)


class CallCapTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(CallCap(10).limit, 10)

    def test_rejects_non_int(self):
        with self.assertRaises(TypeError):
            CallCap(1.5)  # type: ignore[arg-type]

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            CallCap(-1)


class SpendCapTests(unittest.TestCase):
    def test_valid(self):
        c = SpendCap(5.0)
        self.assertEqual(c.usd, 5.0)

    def test_zero_ok(self):
        c = SpendCap(0)
        self.assertEqual(c.usd, 0)

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            SpendCap(-0.01)


if __name__ == "__main__":
    unittest.main()
