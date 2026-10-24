"""
Comprehensive pytest verification suite for ClockedOmniGuard:
- Tests all 10 Clocked endpoints across Group 1, Group 2, Group 3, and Pipeline
- Verifies `stop: true` guardrail short-circuiting on adversarial prompt injection + malicious script
- Verifies all 11 live `clocked-1.0` production responses in `public/live_fixtures.json`
- Verifies 10-tool MCP JSON-RPC 2.0 server and FastAPI REST endpoints
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
from backend.clocked_engine import ClockedOmniEngine, PRESET_SCENARIOS
from backend.mcp_server import handle_mcp_request, MCP_TOOLS
from backend.server import app

FIXTURES_PATH = ROOT_DIR / "public" / "live_fixtures.json"


def test_all_10_clocked_endpoints_engine() -> None:
    engine = ClockedOmniEngine()
    scen_a = PRESET_SCENARIOS[0]
    txt = scen_a["input_text"]

    # Group 2: Protect, Guard, Inspect
    r_pii = engine.pii(txt, action="redact")
    assert r_pii["pii_detected"] is True
    assert r_pii["entity_count"] >= 3
    assert "[REDACTED_EMAIL]" in r_pii["clean_text"]

    r_inj = engine.injection(txt)
    assert r_inj["verdict"] == "safe"

    r_scr = engine.script(scen_a["vendor_script"])
    assert r_scr["verdict"] == "safe"

    # Group 1: Decide, Extract, Fill
    r_dec = engine.decide(txt)
    assert r_dec["selected"] == ["APPROVE_STANDARD_DEAL_DESK"]
    assert r_dec["confidence"] > 0.85

    r_ext = engine.extract(txt)
    assert len(r_ext["answers"]) == 4
    assert r_ext["answers"][0]["found"] is True
    assert r_ext["answers"][0]["start"] >= 0

    r_fill = engine.fill(txt)
    assert r_fill["single_call_schema_populated"] is True
    assert r_fill["values"]["record_category"] == "MSA_CONTRACT"

    # Group 3: Verify, Compare, Rerank
    r_gnd = engine.grounding(txt, scen_a["ai_draft_summary"])
    assert r_gnd["grounded"] is False
    assert r_gnd["supported_claims"] == 2
    assert r_gnd["total_claims"] == 3

    r_cmp = engine.compare(txt, scen_a["baseline_contract_v1"])
    assert r_cmp["verdict"] == "conflict"
    assert r_cmp["conflict_count"] >= 2

    r_rerank = engine.rerank(txt[:160], scen_a["passages"])
    assert r_rerank["results"][0]["action"] == "use"
    assert r_rerank["results"][-1]["action"] == "skip"


def test_pipeline_safe_vs_adversarial_short_circuit() -> None:
    engine = ClockedOmniEngine()

    # Scenario A: Safe full pass (all 9 steps execute)
    pipe_safe = engine.pipeline("scenario-enterprise-msa", stop_on_security_threat=True)
    assert pipe_safe["halted"] is False
    assert pipe_safe["steps_executed"] == 9

    # Scenario B: Adversarial prompt injection + RCE script -> halts at Step 2
    pipe_adv = engine.pipeline("scenario-adversarial-injection", stop_on_security_threat=True)
    assert pipe_adv["halted"] is True
    assert pipe_adv["steps_executed"] == 2
    assert "stop: true" in (pipe_adv["halt_reason"] or "")


def test_live_clocked_1_0_fixtures_verified_and_secret_free() -> None:
    assert FIXTURES_PATH.exists(), "public/live_fixtures.json must exist"
    raw = FIXTURES_PATH.read_text(encoding="utf-8")
    assert ("clk_" + "live_") not in raw, "No API key may ever appear in live_fixtures.json"

    data = json.loads(raw)
    expected_keys = [
        "decide",
        "extract",
        "fill",
        "pii",
        "injection",
        "script",
        "grounding",
        "compare",
        "rerank",
        "pipeline",
        "pipeline_safe",
    ]
    for k in expected_keys:
        assert k in data, f"Missing live fixture for {k}"
        assert data[k]["status"] == 200
        assert data[k]["response"]["model"] == "clocked-1.0"


def test_mcp_10_tools_and_fastapi_routes() -> None:
    engine = ClockedOmniEngine()
    assert len(MCP_TOOLS) == 10

    list_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, engine)
    assert len(list_resp["result"]["tools"]) == 10

    for tool in MCP_TOOLS:
        call_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool["name"], "arguments": {}},
            },
            engine,
        )
        assert "result" in call_resp
        assert call_resp["result"]["tool"] == tool["name"]

    client = TestClient(app)
    h = client.get("/api/health")
    assert h.status_code == 200
    assert h.json()["endpoints_integrated"] == 10
