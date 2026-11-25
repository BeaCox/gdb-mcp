import io
import json
import unittest
from contextlib import redirect_stdout

from gdb_mcp.observability import StructuredLogger, parse_log_level, redact_mapping, redact_text


class ObservabilityTests(unittest.TestCase):
    def test_logger_is_silent_by_default_and_never_writes_stdout(self) -> None:
        buf = io.StringIO()
        log = StructuredLogger(stream=buf)
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            log.emit("info", "session.created", session_id="s1")

        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(stdout_buf.getvalue(), "")

    def test_logger_writes_redacted_json_to_stderr_stream_only(self) -> None:
        buf = io.StringIO()
        log = StructuredLogger(level="info", stream=buf)
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            log.emit(
                "info",
                "session.created",
                session_id="s1",
                token="PLANTED_SECRET_TOKEN",
                args=["PLANTED_ARG"],
                env={"API_KEY": "PLANTED_ENV"},
                note="Authorization: Bearer PLANTED_BEARER https://u:PLANTED_PASS@host/mcp",
            )
            log.emit("debug", "command.finished", detail="filtered out at info level")

        self.assertEqual(stdout_buf.getvalue(), "")
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        encoded = lines[0]
        planted = (
            "PLANTED_SECRET_TOKEN",
            "PLANTED_ARG",
            "PLANTED_ENV",
            "PLANTED_BEARER",
            "PLANTED_PASS",
        )
        for secret in planted:
            self.assertNotIn(secret, encoded)
        record = json.loads(encoded)
        self.assertEqual(record["event"], "session.created")
        self.assertEqual(record["token"], "[REDACTED]")
        self.assertEqual(record["args"], "[REDACTED]")
        self.assertEqual(record["env"], "[REDACTED]")

    def test_parse_log_level_and_redaction_helpers(self) -> None:
        self.assertEqual(parse_log_level(None), "off")
        self.assertEqual(parse_log_level(" INFO "), "info")
        with self.assertRaises(ValueError):
            parse_log_level("verbose")

        self.assertEqual(redact_text("secret=supersecret"), "secret=[REDACTED]")
        mapped = redact_mapping({"password": "p", "nested": {"api_key": "k", "ok": "v"}})
        self.assertEqual(mapped["password"], "[REDACTED]")
        self.assertEqual(mapped["nested"]["api_key"], "[REDACTED]")
        self.assertEqual(mapped["nested"]["ok"], "v")


if __name__ == "__main__":
    unittest.main()
