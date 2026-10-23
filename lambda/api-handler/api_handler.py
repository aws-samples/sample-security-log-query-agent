# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Security Log Query Agent - API handler Lambda.

Natural-language -> read-only Athena SQL over a centralized security-log catalog,
using the Amazon Bedrock Converse API with tool use. Model-agnostic: MODEL_ID may be
a bare model id (e.g. amazon.nova-pro-v1:0) OR an inference-profile id/ARN
(e.g. us.anthropic.claude-sonnet-4-5-20250929-v1:0) - Converse accepts both in modelId.

Runs as a dedicated read-only role. The query path is read-only by construction:
the handler rejects any non-SELECT/WITH SQL and runs it in a locked-down Athena
workgroup against the cross-account Glue Data Catalog (central logs in the Log
Archive account).

Environment:
    MODEL_ID            Bedrock model id or inference-profile id/ARN (required)
    ATHENA_WORKGROUP    locked-down workgroup name (required)
    GLUE_CATALOG_NAME   Athena DataCatalog name for the cross-account catalog (required)
    GLUE_DATABASE       Glue database name (required)
    MAX_TOOL_TURNS      max Converse tool-use turns (default 6)
    AWS_REGION          provided by Lambda runtime
"""
import json
import os
import time
import uuid

import boto3
import sqlglot
from sqlglot import expressions as exp

MODEL_ID = os.environ["MODEL_ID"]
WORKGROUP = os.environ["ATHENA_WORKGROUP"]
CATALOG_NAME = os.environ["GLUE_CATALOG_NAME"]
DATABASE = os.environ["GLUE_DATABASE"]
MAX_TOOL_TURNS = int(os.environ.get("MAX_TOOL_TURNS", "6"))

bedrock = boto3.client("bedrock-runtime")
athena = boto3.client("athena")

# Athena/Trino uses the Presto SQL dialect; parse with that so our structural
# check matches what the engine will actually run.
_SQL_DIALECT = "presto"


def _is_readonly_sql(sql: str) -> bool:
    """Return True only for a SINGLE read-only (SELECT/WITH) statement.

    AST-based, not substring matching: this rejects multi-statement input
    (e.g. a trailing "; DROP TABLE ..."), and never false-positives on a
    forbidden word that appears inside an identifier or string literal.
    """
    try:
        statements = sqlglot.parse(sql, read=_SQL_DIALECT)
    except Exception:  # noqa: BLE001 - any parse failure is treated as unsafe
        return False

    # Exactly one non-empty statement is allowed.
    statements = [s for s in statements if s is not None]
    if len(statements) != 1:
        return False

    root = statements[0]
    # The only read-only top-level forms. A WITH (CTE) that wraps a SELECT
    # parses to a Select whose `with` arg is populated, so Select covers both.
    return isinstance(root, exp.Select)

# System prompt describes the four base log tables so the model can generate SQL.
# Keep table/column facts here; the model needs schema to be accurate.
SYSTEM_PROMPT = (
    "You are a security log query assistant for a cloud security team. Convert the analyst's "
    "question into ONE safe, read-only Amazon Athena SQL query (SELECT only) and call the "
    "run_athena_query tool to execute it, then summarize the returned rows in plain English. "
    "Always add a LIMIT (default 100) and, when possible, a time filter to keep scans small.\n\n"
    f"Database: {DATABASE}. Tables:\n"
    "1) cloudtrail - organization CloudTrail (who did what). Columns: eventtime (string ISO8601), "
    "eventsource, eventname, awsregion, sourceipaddress, useragent, errorcode, errormessage, "
    "recipientaccountid, readonly, useridentity (struct: useridentity.type, useridentity.arn, "
    "useridentity.username, useridentity.sessioncontext.attributes.mfaauthenticated). "
    "Filter time with from_iso8601_timestamp(eventtime) > current_timestamp - interval '1' day. "
    "Failed console logins: eventname='ConsoleLogin' AND errormessage IS NOT NULL. "
    "Role assumptions: eventname='AssumeRole'.\n"
    "2) vpc_flow_logs - network connections. Columns: srcaddr, dstaddr, srcport, dstport, "
    "protocol (6=TCP,17=UDP), bytes, packets, action (ACCEPT/REJECT), account_id, start, end. "
    "Rejected traffic: action='REJECT'.\n"
    "3) guardduty - GuardDuty findings. Columns: id, type, severity (double; >=7 high, 4-6.9 "
    "medium, <4 low), region, accountid, createdat (string), updatedat (string), title, "
    "description, resource_resourcetype, service_action_actiontype. High-severity recent findings: "
    "severity >= 7 ordered by updatedat desc.\n"
    "4) network_firewall - AWS Network Firewall alert/flow logs. Columns: event_timestamp, "
    "event_alert_action, event_alert_signature, event_src_ip, event_dest_ip, event_dest_port, "
    "event_proto, event_app_proto, event_tls_sni. Blocked flows: event_alert_action='blocked'.\n\n"
    "If a query fails, read the error and try once more with a corrected query."
)

TOOL_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "run_athena_query",
                "description": (
                    "Run a single read-only Athena SELECT query against the central security-log "
                    "catalog and return up to 100 rows."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "sql": {"type": "string", "description": "A single read-only SELECT/WITH query."}
                        },
                        "required": ["sql"],
                    }
                },
            }
        }
    ]
}


def _run_athena(sql):
    """Execute a read-only query. Returns {'rows': [...]} or {'error': '...'}."""
    sql = (sql or "").strip().rstrip(";")
    if not _is_readonly_sql(sql):
        return {"error": "Only a single read-only SELECT query is permitted."}
    try:
        qid = athena.start_query_execution(
            QueryString=sql,
            WorkGroup=WORKGROUP,
            QueryExecutionContext={"Database": DATABASE, "Catalog": CATALOG_NAME},
        )["QueryExecutionId"]
        state = "RUNNING"
        for _ in range(50):
            info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            state = info["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(1)
        if state != "SUCCEEDED":
            reason = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"].get(
                "StateChangeReason", "")
            return {"error": f"Query {state.lower()}. {reason}"}
        result = athena.get_query_results(QueryExecutionId=qid, MaxResults=100)
        rows = [[c.get("VarCharValue", "") for c in r["Data"]] for r in result["ResultSet"]["Rows"]]
        return {"rows": rows}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def _converse(messages):
    return bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=messages,
        toolConfig=TOOL_CONFIG,
        inferenceConfig={"maxTokens": 1024, "temperature": 0},
    )


def handler(event, _context):
    try:
        body = json.loads(event.get("body") or "{}")
        question = (body.get("question") or "").strip()
        session_id = body.get("sessionId") or str(uuid.uuid4())
        if not question:
            return _resp(400, {"error": "Missing 'question'."})

        messages = [{"role": "user", "content": [{"text": question}]}]
        last_sql = None

        for _turn in range(MAX_TOOL_TURNS):
            resp = _converse(messages)
            out = resp["output"]["message"]
            messages.append(out)

            tool_use = next((b["toolUse"] for b in out.get("content", []) if "toolUse" in b), None)
            if tool_use is None:
                answer = " ".join(b.get("text", "") for b in out.get("content", []) if "text" in b).strip()
                return _resp(200, {"sessionId": session_id, "answer": answer, "sql": last_sql})

            last_sql = tool_use.get("input", {}).get("sql")
            result = _run_athena(last_sql)
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {"toolResult": {"toolUseId": tool_use["toolUseId"], "content": [{"json": result}]}}
                    ],
                }
            )

        return _resp(200, {"sessionId": session_id,
                           "answer": "Stopped after the maximum tool turns without a final answer.",
                           "sql": last_sql})
    except Exception as exc:  # noqa: BLE001
        return _resp(500, {"error": str(exc)})


def _resp(status, payload):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(payload)}
