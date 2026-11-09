# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the API handler's response deadline, audit records, and error handling.

Athena, Bedrock, and the clock are replaced with in-memory fakes, so these tests
reach no AWS service and do not sleep.
"""
import json
import types

import pytest

import api_handler


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeAthena:
    """Reports RUNNING `running_polls` times, then `final_state`."""

    def __init__(self, running_polls=0, final_state="SUCCEEDED", rows=None, start_error=None):
        self.running_polls = running_polls
        self.final_state = final_state
        self.rows = rows if rows is not None else [["col"], ["value"]]
        self.start_error = start_error
        self.started = []
        self.stopped = []

    def start_query_execution(self, **kwargs):
        if self.start_error is not None:
            raise self.start_error
        self.started.append(kwargs["QueryString"])
        return {"QueryExecutionId": f"qid-{len(self.started)}"}

    def get_query_execution(self, QueryExecutionId):
        if self.running_polls > 0:
            self.running_polls -= 1
            state = "RUNNING"
        else:
            state = self.final_state
        return {"QueryExecution": {"Status": {"State": state, "StateChangeReason": "reason"}}}

    def stop_query_execution(self, QueryExecutionId):
        self.stopped.append(QueryExecutionId)
        return {}

    def get_query_results(self, QueryExecutionId, MaxResults):
        return {"ResultSet": {"Rows": [{"Data": [{"VarCharValue": v} for v in row]} for row in self.rows]}}


class FakeBedrock:
    """Returns the scripted Converse messages in order."""

    def __init__(self, messages, clock=None, seconds_per_call=0.0):
        self.messages = list(messages)
        self.clock = clock
        self.seconds_per_call = seconds_per_call
        self.calls = 0

    def converse(self, **_kwargs):
        self.calls += 1
        if self.clock is not None:
            self.clock.now += self.seconds_per_call
        return {"output": {"message": self.messages.pop(0)}}


def tool_use(sql, tool_use_id="t1"):
    return {"role": "assistant", "content": [{"toolUse": {"toolUseId": tool_use_id, "input": {"sql": sql}}}]}


def final_text(text):
    return {"role": "assistant", "content": [{"text": text}]}


def audit_records(capsys):
    records = []
    for line in capsys.readouterr().out.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and "audit" in record:
            records.append(record)
    return records


def api_event(question, sub="alice-sub", upn="alice@example.com"):
    return {
        "body": json.dumps({"question": question}),
        "requestContext": {"authorizer": {"principalId": sub, "sub": sub, "upn": upn}},
    }


CONTEXT = types.SimpleNamespace(aws_request_id="req-123")


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(api_handler, "time", fake)
    return fake


class TestRunAthena:
    def test_query_past_deadline_is_stopped_not_abandoned(self, monkeypatch, clock, capsys):
        athena = FakeAthena(running_polls=1000)
        monkeypatch.setattr(api_handler, "athena", athena)

        result = api_handler._run_athena("SELECT 1", clock.now + 5, "req-1")

        assert athena.stopped == ["qid-1"]
        assert result["queryExecutionId"] == "qid-1"
        assert "stopped" in result["error"]
        assert "rows" not in result
        assert any(r["audit"] == "query_stopped" for r in audit_records(capsys))

    def test_successful_query_returns_rows_and_query_id(self, monkeypatch, clock):
        athena = FakeAthena(running_polls=2)
        monkeypatch.setattr(api_handler, "athena", athena)

        result = api_handler._run_athena("SELECT 1", clock.now + 20, "req-1")

        assert result == {"rows": [["col"], ["value"]], "queryExecutionId": "qid-1"}
        assert athena.stopped == []

    def test_long_cells_are_capped_before_reaching_the_model(self, monkeypatch, clock):
        payload = "x" * (api_handler.MAX_CELL_CHARS + 50)
        monkeypatch.setattr(api_handler, "athena", FakeAthena(rows=[[payload]]))

        cell = api_handler._run_athena("SELECT 1", clock.now + 20, "req-1")["rows"][0][0]

        assert cell.startswith("x" * api_handler.MAX_CELL_CHARS)
        assert cell.endswith("...[truncated]")
        assert len(cell) < len(payload)

    def test_rejected_sql_is_audited_and_never_reaches_athena(self, monkeypatch, clock, capsys):
        athena = FakeAthena()
        monkeypatch.setattr(api_handler, "athena", athena)
        mutating = "DR" + "OP TABLE cloudtrail"

        result = api_handler._run_athena(mutating, clock.now + 20, "req-1")

        assert "Only a single read-only SELECT" in result["error"]
        assert athena.started == []
        rejected = [r for r in audit_records(capsys) if r["audit"] == "sql_rejected"]
        assert rejected and rejected[0]["sql"] == mutating

    def test_invalid_request_message_is_returned_for_query_correction(self, monkeypatch, clock):
        error = Exception("boom")
        error.response = {"Error": {"Code": "InvalidRequestException", "Message": "line 1:8: column x"}}
        monkeypatch.setattr(api_handler, "athena", FakeAthena(start_error=error))

        result = api_handler._run_athena("SELECT x", clock.now + 20, "req-1")

        assert result["error"] == "line 1:8: column x"

    def test_other_errors_are_not_returned_to_the_model(self, monkeypatch, clock, capsys):
        error = Exception("arn:aws:iam::123456789012:role/secret-detail")
        monkeypatch.setattr(api_handler, "athena", FakeAthena(start_error=error))

        result = api_handler._run_athena("SELECT 1", clock.now + 20, "req-1")

        assert result["error"] == "The query could not be run."
        assert "123456789012" not in json.dumps(result)
        assert any("123456789012" in r.get("error", "") for r in audit_records(capsys))


class TestHandler:
    def test_answer_includes_sql_and_query_ids_and_is_audited(self, monkeypatch, clock, capsys):
        monkeypatch.setattr(api_handler, "athena", FakeAthena())
        monkeypatch.setattr(
            api_handler, "bedrock", FakeBedrock([tool_use("SELECT 1"), final_text("One event.")])
        )

        response = api_handler.handler(api_event("How many events?"), CONTEXT)

        body = json.loads(response["body"])
        assert response["statusCode"] == 200
        assert body["answer"] == "One event."
        assert body["sql"] == "SELECT 1"
        assert body["queryExecutionIds"] == ["qid-1"]
        records = audit_records(capsys)
        received = next(r for r in records if r["audit"] == "request_received")
        assert received["requestId"] == "req-123"
        assert received["question"] == "How many events?"
        assert received["caller"] == {"principalId": "alice-sub", "sub": "alice-sub", "upn": "alice@example.com"}
        finished = next(r for r in records if r["audit"] == "request_finished")
        assert finished["outcome"] == "answered"
        assert finished["queryExecutionIds"] == ["qid-1"]

    def test_no_new_model_turn_starts_after_the_deadline(self, monkeypatch, clock, capsys):
        monkeypatch.setattr(api_handler, "athena", FakeAthena())
        # Each Converse call takes longer than the whole response budget.
        bedrock = FakeBedrock(
            [tool_use("SELECT 1"), final_text("never reached")],
            clock=clock,
            seconds_per_call=api_handler.RESPONSE_DEADLINE_SECONDS + 1,
        )
        monkeypatch.setattr(api_handler, "bedrock", bedrock)

        response = api_handler.handler(api_event("How many events?"), CONTEXT)

        body = json.loads(response["body"])
        assert response["statusCode"] == 200
        assert bedrock.calls == 1
        assert body["answer"].startswith("Stopped: the response time budget")
        finished = next(r for r in audit_records(capsys) if r["audit"] == "request_finished")
        assert finished["outcome"] == "deadline"

    def test_internal_error_returns_generic_body(self, monkeypatch, clock, capsys):
        class Failing:
            def converse(self, **_kwargs):
                raise RuntimeError("internal detail arn:aws:bedrock:us-east-1:123456789012:x")

        monkeypatch.setattr(api_handler, "bedrock", Failing())

        response = api_handler.handler(api_event("How many events?"), CONTEXT)

        body = json.loads(response["body"])
        assert response["statusCode"] == 500
        assert body == {"error": "Internal error.", "requestId": "req-123"}
        assert any(r["audit"] == "request_error" for r in audit_records(capsys))

    def test_missing_question_is_rejected_and_audited(self, clock, capsys):
        response = api_handler.handler({"body": "{}"}, CONTEXT)

        assert response["statusCode"] == 400
        finished = next(r for r in audit_records(capsys) if r["audit"] == "request_finished")
        assert finished["outcome"] == "bad_request"


class TestInferenceConfig:
    def test_temperature_is_omitted_when_not_configured(self, monkeypatch):
        # Some current models reject `temperature`, so the default request must not carry it.
        monkeypatch.setattr(api_handler, "MODEL_TEMPERATURE", None)

        assert api_handler._inference_config() == {"maxTokens": 1024}

    def test_temperature_is_sent_when_configured(self, monkeypatch):
        monkeypatch.setattr(api_handler, "MODEL_TEMPERATURE", 0.0)

        assert api_handler._inference_config() == {"maxTokens": 1024, "temperature": 0.0}
