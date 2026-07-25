import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from gdb_mcp.compatibility import FEATURE_PROBES, probe_gdb_features


class CompatibilityProbeTests(unittest.TestCase):
    def test_missing_gdb_has_actionable_feature_reasons(self) -> None:
        features = asyncio.run(probe_gdb_features(None))

        self.assertEqual(set(features), set(FEATURE_PROBES))
        self.assertTrue(all(not item["supported"] for item in features.values()))
        self.assertTrue(all("not available" in item["reason"] for item in features.values()))

    def test_probe_uses_command_results_instead_of_version(self) -> None:
        results = [(0, "available"), (1, "Undefined command")] + [
            (0, "available")
        ] * (len(FEATURE_PROBES) - 2)
        with patch(
            "gdb_mcp.compatibility._run_probe",
            new=AsyncMock(side_effect=results),
        ):
            features = asyncio.run(probe_gdb_features("/usr/bin/gdb"))

        names = list(FEATURE_PROBES)
        self.assertTrue(features[names[0]]["supported"])
        self.assertFalse(features[names[1]]["supported"])
        self.assertEqual(features[names[1]]["reason"], "Undefined command")


if __name__ == "__main__":
    unittest.main()
