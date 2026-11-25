import asyncio
import unittest

from gdb_mcp.eval_harness import run_all_scenarios


class EvalHarnessTests(unittest.TestCase):
    def test_all_deterministic_scenarios_pass_within_budget_without_leaks(self) -> None:
        report = asyncio.run(run_all_scenarios())
        self.assertTrue(report.ok, report.format_table())
        self.assertEqual(len(report.scenarios), 5)
        for item in report.scenarios:
            with self.subTest(scenario=item.name):
                self.assertTrue(item.completed, item.failures)
                self.assertTrue(item.within_budget, item.failures)
                self.assertEqual(item.leaked_sessions, 0)


if __name__ == "__main__":
    unittest.main()
