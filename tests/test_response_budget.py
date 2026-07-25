import unittest

from gdb_mcp.response_budget import estimate_tokens, measure_response, serialize_response


class ResponseBudgetTests(unittest.TestCase):
    def test_serialization_is_deterministic_and_utf8_aware(self) -> None:
        left = {"z": "debug", "a": "路径"}
        right = {"a": "路径", "z": "debug"}

        self.assertEqual(serialize_response(left), serialize_response(right))
        self.assertEqual(measure_response(left).bytes, len(serialize_response(left)))

    def test_token_estimate_rounds_up_at_three_bytes(self) -> None:
        self.assertEqual(estimate_tokens(0), 0)
        self.assertEqual(estimate_tokens(1), 1)
        self.assertEqual(estimate_tokens(3), 1)
        self.assertEqual(estimate_tokens(4), 2)
        with self.assertRaisesRegex(ValueError, "non-negative"):
            estimate_tokens(-1)


if __name__ == "__main__":
    unittest.main()
