import unittest

from gdb_mcp.contract import build_contract_snapshot, diff_contract


def _sample_snapshot():
    return build_contract_snapshot(
        capabilities={"tools": {"listChanged": False}, "resources": {}, "prompts": {}},
        profiles={
            "core": [
                {
                    "name": "gdb_context",
                    "description": "Context",
                    "inputSchema": {
                        "type": "object",
                        "required": ["session_id"],
                        "properties": {
                            "session_id": {"type": "string"},
                            "output": {"type": "string"},
                        },
                    },
                    "annotations": {"readOnlyHint": True, "destructiveHint": False},
                }
            ]
        },
        resources=[
            {
                "uri": "gdb://workflows/basic",
                "name": "basic",
                "mimeType": "application/json",
            }
        ],
        prompts=[
            {
                "name": "debug_local",
                "arguments": [{"name": "program", "required": True}],
            }
        ],
    )


class ContractDiffTests(unittest.TestCase):
    def test_identical_contracts_produce_empty_ok_diff(self) -> None:
        base = _sample_snapshot()
        diff = diff_contract(base, _sample_snapshot())
        self.assertTrue(diff.ok)
        self.assertEqual(diff.breaking, [])
        self.assertEqual(diff.additive, [])

    def test_additive_changes_are_allowed(self) -> None:
        base = _sample_snapshot()
        cur = _sample_snapshot()
        cur["profiles"]["core"]["gdb_context"]["inputSchema"]["properties"]["max_frames"] = {
            "type": "integer"
        }
        cur["profiles"]["core"]["gdb_new"] = {
            "name": "gdb_new",
            "description": "New tool",
            "inputSchema": {"type": "object", "required": [], "properties": {}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        }
        cur["resources"]["gdb://workflows/new"] = {
            "uri": "gdb://workflows/new",
            "name": "new",
            "mimeType": "application/json",
        }
        cur["prompts"]["debug_local"]["arguments"]["cwd"] = {"required": False}

        diff = diff_contract(base, cur)
        self.assertTrue(diff.ok)
        self.assertEqual(diff.breaking, [])
        self.assertEqual(len(diff.additive), 4)

    def test_breaking_changes_are_rejected(self) -> None:
        base = _sample_snapshot()
        cur = _sample_snapshot()
        del cur["profiles"]["core"]["gdb_context"]["inputSchema"]["properties"]["output"]
        cur["profiles"]["core"]["gdb_context"]["inputSchema"]["properties"]["mode"] = {
            "type": "string"
        }
        cur["profiles"]["core"]["gdb_context"]["inputSchema"]["required"].append("mode")
        cur["profiles"]["core"]["gdb_context"]["annotations"]["readOnlyHint"] = False
        del cur["resources"]["gdb://workflows/basic"]
        cur["prompts"]["debug_local"]["arguments"]["target"] = {"required": True}

        diff = diff_contract(base, cur)
        self.assertFalse(diff.ok)
        self.assertGreaterEqual(len(diff.breaking), 5)
        self.assertIn("Breaking changes:", diff.format_report())


if __name__ == "__main__":
    unittest.main()
