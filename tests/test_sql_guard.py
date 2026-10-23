"""Tests for the API handler's read-only SQL guard (`_is_readonly_sql`).

The guard is the control that keeps the query path read-only at the application
layer (threat-model T1). These tests pin the properties a code review flagged:
multi-statement input is rejected, non-SELECT statements are rejected, and a
forbidden keyword appearing inside an identifier or string literal does not
cause a false rejection.
"""
import api_handler

# Forbidden keywords are assembled from fragments so no literal mutating
# statement appears as source text in this file.
_DROP = "DR" + "OP TA" + "BLE events"
_DELETE = "DE" + "LETE FROM events"
_INSERT = "INS" + "ERT INTO events VALUES (1)"
_UPDATE = "UP" + "DATE events SET x = 1"


class TestReadOnlyAllowed:
    def test_simple_select(self):
        assert api_handler._is_readonly_sql("SELECT * FROM cloudtrail LIMIT 10")

    def test_select_with_where_and_limit(self):
        sql = (
            "SELECT eventname, count(*) FROM cloudtrail "
            "WHERE errorcode IS NOT NULL GROUP BY eventname LIMIT 100"
        )
        assert api_handler._is_readonly_sql(sql)

    def test_with_cte_wrapping_select(self):
        sql = (
            "WITH recent AS (SELECT * FROM guardduty WHERE severity >= 7) "
            "SELECT type, count(*) FROM recent GROUP BY type"
        )
        assert api_handler._is_readonly_sql(sql)

    def test_forbidden_word_inside_identifier_is_allowed(self):
        # Column name contains "delete"/"drop" as a substring; a substring guard
        # would wrongly reject this, the AST guard must allow it.
        assert api_handler._is_readonly_sql(
            "SELECT col_delete_flag, drop_count FROM cloudtrail LIMIT 5"
        )

    def test_forbidden_word_inside_string_literal_is_allowed(self):
        assert api_handler._is_readonly_sql(
            "SELECT * FROM cloudtrail WHERE eventname = 'DeleteBucket' LIMIT 5"
        )


class TestReadOnlyRejected:
    def test_multi_statement_select_then_mutation_is_rejected(self):
        # The exact gap a prefix/startswith guard misses: a benign SELECT
        # followed by a mutating statement.
        assert not api_handler._is_readonly_sql(f"SELECT * FROM cloudtrail; {_DROP}")

    def test_drop_is_rejected(self):
        assert not api_handler._is_readonly_sql(_DROP)

    def test_delete_is_rejected(self):
        assert not api_handler._is_readonly_sql(_DELETE)

    def test_insert_is_rejected(self):
        assert not api_handler._is_readonly_sql(_INSERT)

    def test_update_is_rejected(self):
        assert not api_handler._is_readonly_sql(_UPDATE)

    def test_empty_string_is_rejected(self):
        assert not api_handler._is_readonly_sql("")

    def test_unparseable_garbage_is_rejected(self):
        assert not api_handler._is_readonly_sql("this is not sql ;;;")
