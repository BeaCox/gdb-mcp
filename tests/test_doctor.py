import asyncio
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from gdb_mcp.doctor import collect_doctor_report, format_doctor_report, run_doctor


def _healthy_which(name: str) -> str | None:
    return {
        "gdb": "/usr/bin/gdb",
        "gdbserver": "/usr/bin/gdbserver",
        "rr": "/usr/bin/rr",
        "claude": "/usr/local/bin/claude",
    }.get(name)


async def _healthy_features(_gdb_path: str | None) -> dict[str, dict]:
    return {
        "mi2": {"supported": True, "reason": None},
        "python": {"supported": True, "reason": None},
        "record_full": {"supported": True, "reason": None},
        "reverse_execution": {"supported": True, "reason": None},
        "gcore": {"supported": True, "reason": None},
        "target_extended_remote": {"supported": True, "reason": None},
        "debuginfod": {"supported": True, "reason": None},
    }


class DoctorTests(unittest.TestCase):
    def test_healthy_environment_reports_ok_and_client_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ptrace = root / "ptrace_scope"
            ptrace.write_text("0\n", encoding="utf-8")
            perf = root / "perf_event_paranoid"
            perf.write_text("1\n", encoding="utf-8")
            status = root / "status"
            status.write_text("CapEff:\t000001ffffffffff\n", encoding="utf-8")
            cgroup = root / "cgroup"
            cgroup.write_text("0::/\n", encoding="utf-8")
            home = root / "home"
            home.mkdir()
            (home / ".claude.json").write_text('{"mcpServers":{"gdb":{}}}', encoding="utf-8")
            agy_dir = home / ".gemini" / "config"
            agy_dir.mkdir(parents=True)
            (agy_dir / "mcp_config.json").write_text(
                '{"mcpServers":{"gdb":{"command":"gdb-mcp"}}}',
                encoding="utf-8",
            )

            with (
                patch("gdb_mcp.doctor.shutil.which", side_effect=_healthy_which),
                patch("gdb_mcp.doctor._executable_version", return_value="GNU gdb 15.0"),
                patch("gdb_mcp.doctor.probe_gdb_features", side_effect=_healthy_features),
            ):
                report = asyncio.run(
                    collect_doctor_report(
                        ptrace_scope_path=ptrace,
                        perf_paranoid_path=perf,
                        proc_status_path=status,
                        cgroup_path=cgroup,
                        container_marker_paths=(root / "missing-dockerenv",),
                        home_dir=home,
                    )
                )

        self.assertTrue(report["ok"], report)
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertEqual(report["summary"]["warn"], 0)
        text = format_doctor_report(report)
        self.assertIn("beacox-gdb-mcp", text)
        self.assertIn("[OK  ] gdb:", text)
        self.assertIn("Registered in: claude, antigravity", text)

    def test_missing_gdb_and_restricted_container_produce_actionable_fixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ptrace = root / "ptrace_scope"
            ptrace.write_text("1\n", encoding="utf-8")
            perf = root / "perf_event_paranoid"
            perf.write_text("2\n", encoding="utf-8")
            status = root / "status"
            status.write_text("CapEff:\t0000000000000000\n", encoding="utf-8")
            cgroup = root / "cgroup"
            cgroup.write_text("0::/docker/abc\n", encoding="utf-8")
            marker = root / ".dockerenv"
            marker.write_text("", encoding="utf-8")
            home = root / "home"
            home.mkdir()

            with (
                patch(
                    "gdb_mcp.doctor.shutil.which",
                    side_effect=lambda name: "/usr/bin/rr" if name == "rr" else None,
                ),
                patch("gdb_mcp.doctor._executable_version", return_value="rr 5.8"),
            ):
                report = asyncio.run(
                    collect_doctor_report(
                        ptrace_scope_path=ptrace,
                        perf_paranoid_path=perf,
                        proc_status_path=status,
                        cgroup_path=cgroup,
                        container_marker_paths=(marker,),
                        home_dir=home,
                    )
                )

        self.assertFalse(report["ok"])
        by_name = {item["name"]: item for item in report["checks"]}
        self.assertEqual(by_name["gdb"]["status"], "fail")
        self.assertIn("apt-get install -y gdb", by_name["gdb"]["fix"])
        self.assertEqual(by_name["ptrace_scope"]["status"], "warn")
        self.assertIn("kernel.yama.ptrace_scope=0", by_name["ptrace_scope"]["fix"])
        self.assertEqual(by_name["perf_event_paranoid"]["status"], "warn")
        self.assertIn("kernel.perf_event_paranoid=1", by_name["perf_event_paranoid"]["fix"])
        self.assertEqual(by_name["container"]["status"], "warn")
        self.assertIn("--cap-add=SYS_PTRACE", by_name["container"]["fix"])

    def test_run_doctor_json_returns_zero_on_ok(self) -> None:
        fake_report = {
            "ok": True,
            "distribution": "beacox-gdb-mcp",
            "version": "0.5.0",
            "python": "3.12.0",
            "platform": "Linux",
            "checks": [],
            "summary": {"ok": 1, "warn": 0, "info": 0, "fail": 0},
        }
        async def _fake_collect():
            return fake_report

        buf = io.StringIO()
        with (
            patch("gdb_mcp.doctor.collect_doctor_report", side_effect=_fake_collect),
            redirect_stdout(buf),
        ):
            code = run_doctor(as_json=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["distribution"], "beacox-gdb-mcp")


if __name__ == "__main__":
    unittest.main()
