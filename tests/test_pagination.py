import unittest

from gdb_mcp.pagination import CursorError, paginate_items, paginate_range


class OpaquePaginationTests(unittest.TestCase):
    def test_complete_traversal_has_no_duplicates(self) -> None:
        rows = [{"id": index} for index in range(11)]
        cursor = None
        traversed = []

        while True:
            page, metadata = paginate_items(
                rows,
                cursor=cursor,
                page_size=3,
                default_page_size=3,
                max_page_size=10,
                cursor_scope="session:a:symbols",
                _now=100,
            )
            traversed.extend(row["id"] for row in page)
            cursor = metadata["next_cursor"]
            if cursor is None:
                break

        self.assertEqual(traversed, list(range(11)))
        self.assertEqual(len(traversed), len(set(traversed)))

    def test_cursor_rejects_cross_session_reuse(self) -> None:
        rows = [1, 2, 3]
        _, metadata = paginate_items(
            rows,
            cursor=None,
            page_size=1,
            default_page_size=1,
            max_page_size=3,
            cursor_scope="session:a:events",
            _now=100,
        )

        with self.assertRaisesRegex(CursorError, "collection or session"):
            paginate_items(
                rows,
                cursor=metadata["next_cursor"],
                page_size=1,
                default_page_size=1,
                max_page_size=3,
                cursor_scope="session:b:events",
                _now=101,
            )

    def test_cursor_rejects_mutated_snapshot(self) -> None:
        _, metadata = paginate_items(
            ["a", "b", "c"],
            cursor=None,
            page_size=1,
            default_page_size=1,
            max_page_size=3,
            cursor_scope="session:a:commands",
            _now=100,
        )

        with self.assertRaisesRegex(CursorError, "stale cursor"):
            paginate_items(
                ["a", "changed", "c"],
                cursor=metadata["next_cursor"],
                page_size=1,
                default_page_size=1,
                max_page_size=3,
                cursor_scope="session:a:commands",
                _now=101,
            )

    def test_cursor_rejects_expiry_and_tampering(self) -> None:
        _, metadata = paginate_items(
            [1, 2],
            cursor=None,
            page_size=1,
            default_page_size=1,
            max_page_size=2,
            cursor_scope="session:a:events",
            cursor_ttl_seconds=5,
            _now=100,
        )
        cursor = metadata["next_cursor"]
        assert cursor is not None
        prefix, payload, signature = cursor.split(".")
        tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        tampered_cursor = f"{prefix}.{payload}.{tampered_signature}"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        alias_index = alphabet.index(signature[-1]) + 1
        noncanonical_cursor = f"{prefix}.{payload}.{signature[:-1]}{alphabet[alias_index]}"

        with self.assertRaisesRegex(CursorError, "expired cursor"):
            paginate_items(
                [1, 2],
                cursor=cursor,
                page_size=1,
                default_page_size=1,
                max_page_size=2,
                cursor_scope="session:a:events",
                cursor_ttl_seconds=5,
                _now=105,
            )

        with self.assertRaisesRegex(CursorError, "invalid cursor"):
            paginate_items(
                [1, 2],
                cursor=tampered_cursor,
                page_size=1,
                default_page_size=1,
                max_page_size=2,
                cursor_scope="session:a:events",
                _now=101,
            )

        with self.assertRaisesRegex(CursorError, "invalid cursor"):
            paginate_items(
                [1, 2],
                cursor=noncanonical_cursor,
                page_size=1,
                default_page_size=1,
                max_page_size=2,
                cursor_scope="session:a:events",
                _now=101,
            )

    def test_range_cursor_uses_external_snapshot_version(self) -> None:
        _, _, metadata = paginate_range(
            16,
            cursor=None,
            page_size=4,
            default_page_size=4,
            max_page_size=16,
            cursor_scope="session:a:memory:sp:16",
            snapshot="version-1",
            _now=100,
        )

        with self.assertRaisesRegex(CursorError, "stale cursor"):
            paginate_range(
                16,
                cursor=metadata["next_cursor"],
                page_size=4,
                default_page_size=4,
                max_page_size=16,
                cursor_scope="session:a:memory:sp:16",
                snapshot="version-2",
                _now=101,
            )


if __name__ == "__main__":
    unittest.main()
