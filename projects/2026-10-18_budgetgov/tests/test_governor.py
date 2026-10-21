from __future__ import annotations

import threading
import time
import unittest

from tests import support  # noqa: F401

from budgetgov import (
    BudgetExceeded,
    CallCap,
    Governor,
    SessionLocked,
    SpendCap,
    TimeCap,
    TokenCap,
)


class GovernorBasics(unittest.TestCase):
    def test_no_caps_allows_anything(self):
        gov = Governor()
        with gov.session() as s:
            for _ in range(10):
                s.before_call()
                s.after_call()
            self.assertFalse(s.is_sealed)
            self.assertEqual(s.used["calls"], 10)

    def test_opens_logs_closes_with_no_record_path(self):
        # Just makes sure record_path=None is safe.
        gov = Governor(call_cap=CallCap(3))
        with gov.session() as s:
            s.before_call()
            s.after_call()


class CallCapBehavior(unittest.TestCase):
    def test_hits_cap_exactly(self):
        gov = Governor(call_cap=CallCap(3))
        with gov.session() as s:
            for _ in range(3):
                s.before_call()
                s.after_call()
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call()
            self.assertEqual(cm.exception.cap_name, "call")
            self.assertTrue(s.is_sealed)

    def test_sealed_session_refuses_further_calls(self):
        gov = Governor(call_cap=CallCap(1))
        with gov.session() as s:
            s.before_call()
            s.after_call()
            with self.assertRaises(BudgetExceeded):
                s.before_call()
            with self.assertRaises(SessionLocked):
                s.before_call()


class TokenCapBehavior(unittest.TestCase):
    def test_requires_estimate(self):
        gov = Governor(token_cap=TokenCap(1000))
        with gov.session() as s:
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call()  # no estimate
            self.assertEqual(cm.exception.cap_name, "token")
            self.assertTrue(s.is_sealed)

    def test_reservation_counts_against_cap(self):
        gov = Governor(token_cap=TokenCap(1000))
        with gov.session() as s:
            s.before_call(estimated_tokens=600)
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call(estimated_tokens=500)
            self.assertEqual(cm.exception.cap_name, "token")

    def test_actuals_reconcile(self):
        gov = Governor(token_cap=TokenCap(1000))
        with gov.session() as s:
            s.before_call(estimated_tokens=400)
            s.after_call(actual_tokens=350)
            self.assertEqual(s.used["tokens"], 350)
            s.before_call(estimated_tokens=400)
            s.after_call(actual_tokens=200)
            self.assertEqual(s.used["tokens"], 550)

    def test_actual_overshoot_seals(self):
        gov = Governor(token_cap=TokenCap(100))
        with gov.session() as s:
            s.before_call(estimated_tokens=50)
            s.after_call(actual_tokens=200)  # overshot
            self.assertTrue(s.is_sealed)
            with self.assertRaises(SessionLocked):
                s.before_call(estimated_tokens=1)


class SpendCapBehavior(unittest.TestCase):
    def test_requires_estimate(self):
        gov = Governor(spend_cap=SpendCap(1.0))
        with gov.session() as s:
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call()
            self.assertEqual(cm.exception.cap_name, "spend")

    def test_counts_each_reservation(self):
        gov = Governor(spend_cap=SpendCap(1.0))
        with gov.session() as s:
            s.before_call(estimated_cost_usd=0.4)
            s.after_call(actual_cost_usd=0.4)
            s.before_call(estimated_cost_usd=0.4)
            s.after_call(actual_cost_usd=0.4)
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call(estimated_cost_usd=0.4)
            self.assertEqual(cm.exception.cap_name, "spend")


class TimeCapBehavior(unittest.TestCase):
    def test_elapsed_cap_fires(self):
        gov = Governor(time_cap=TimeCap(0.05))
        with gov.session() as s:
            time.sleep(0.1)
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call()
            self.assertEqual(cm.exception.cap_name, "time")


class MixedCapsAndOrder(unittest.TestCase):
    def test_time_wins_when_simultaneously_over(self):
        gov = Governor(
            time_cap=TimeCap(0.05),
            call_cap=CallCap(0),
        )
        with gov.session() as s:
            time.sleep(0.1)
            with self.assertRaises(BudgetExceeded) as cm:
                s.before_call()
            # Time is checked first.
            self.assertEqual(cm.exception.cap_name, "time")


class ValidationErrors(unittest.TestCase):
    def test_rejects_negative_estimates(self):
        gov = Governor(token_cap=TokenCap(100))
        with gov.session() as s:
            with self.assertRaises(ValueError):
                s.before_call(estimated_tokens=-1)

    def test_after_without_before_raises(self):
        gov = Governor()
        with gov.session() as s:
            with self.assertRaises(RuntimeError):
                s.after_call()


class ConcurrencySmoke(unittest.TestCase):
    def test_shared_session_is_thread_safe(self):
        gov = Governor(call_cap=CallCap(50))
        with gov.session() as s:
            def run():
                for _ in range(5):
                    try:
                        s.before_call()
                        s.after_call()
                    except BudgetExceeded:
                        return
            ts = [threading.Thread(target=run) for _ in range(10)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            # Exact: cap was 50 and 10 threads each ran 5 calls.
            self.assertLessEqual(s.used["calls"], 50)


if __name__ == "__main__":
    unittest.main()
