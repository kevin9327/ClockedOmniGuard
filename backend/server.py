"""
ClockedOmniGuard — FastAPI Backend & 10-Tool MCP Server
Serves all 10 Clocked endpoints, preset enterprise/adversarial/clinical scenarios,
verified `clocked-1.0` production fixtures, and static frontend workbench.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .clocked_engine import ClockedOmniEngine, PRESET_SCENARIOS, ENDPOINT_CREDITS, CREDIT_USD_RATE
from .mcp_server import handle_mcp_request, MCP_TOOLS

ROOT_DIR = Path(__file__).resolve().parent.parent
PUBLIC_DIR = ROOT_DIR / "public"
FIXTURES_PATH = PUBLIC_DIR / "live_fixtures.json"

app = FastAPI(
    title="ClockedOmniGuard — 10-Endpoint Enterprise Deal-Room, DevSecOps & Autonomous Agent Security Gateway",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ClockedOmniEngine()


class PipelineRequest(BaseModel):
    scenario_id: str = "scenario-enterprise-msa"
    custom_input: Optional[str] = None
    stop_on_security_threat: bool = True


class EndpointTestRequest(BaseModel):
    endpoint: str
    scenario_id: str = "scenario-enterprise-msa"
    input_text: Optional[str] = None
    secondary_text: Optional[str] = None
    script_text: Optional[str] = None
    ai_summary: Optional[str] = None
    action: str = "redact"
    mode: str = "single_label"


@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    fixtures_loaded = FIXTURES_PATH.exists()
    return {
        "status": "ok",
        "service": "ClockedOmniGuard",
        "model": "clocked-1.0",
        "endpoints_integrated": 10,
        "groups_covered": [
            "Group 1: Decide, Extract, or Fill (/clocked/decide, /clocked/extract, /clocked/fill)",
            "Group 2: Protect, Guard, or Inspect (/clocked/pii, /clocked/injection, /clocked/script)",
            "Group 3: Verify, Compare, or Rerank (/clocked/grounding, /clocked/compare, /clocked/rerank)",
            "10th Endpoint: Single-Admission Chained Pipeline (/clocked/pipeline)",
        ],
        "mcp_tools_count": len(MCP_TOOLS),
        "live_fixtures_available": fixtures_loaded,
    }


@app.get("/api/scenarios")
def get_scenarios() -> Dict[str, Any]:
    return {
        "scenarios": PRESET_SCENARIOS,
        "endpoint_credits": ENDPOINT_CREDITS,
        "credit_usd_rate": CREDIT_USD_RATE,
    }


@app.get("/api/live-fixtures")
def get_live_fixtures() -> Dict[str, Any]:
    if FIXTURES_PATH.exists():
        return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    return {}


@app.post("/api/pipeline")
def run_pipeline(req: PipelineRequest) -> Dict[str, Any]:
    return engine.pipeline(
        scenario_id=req.scenario_id,
        custom_input=req.custom_input,
        stop_on_security_threat=req.stop_on_security_threat,
    )


@app.post("/api/endpoint")
def run_single_endpoint(req: EndpointTestRequest) -> Dict[str, Any]:
    scen = next((s for s in PRESET_SCENARIOS if s["id"] == req.scenario_id), PRESET_SCENARIOS[0])
    txt = req.input_text or scen["input_text"]
    sec = req.secondary_text or scen["baseline_contract_v1"]
    scr = req.script_text or scen["vendor_script"]
    ans = req.ai_summary or scen["ai_draft_summary"]

    ep = req.endpoint.lower().strip("/")
    if ep == "decide":
        return engine.decide(txt, mode=req.mode)
    if ep == "extract":
        return engine.extract(txt)
    if ep == "fill":
        return engine.fill(txt)
    if ep == "pii":
        return engine.pii(txt, action=req.action)
    if ep == "injection":
        return engine.injection(txt)
    if ep == "script":
        return engine.script(scr)
    if ep == "grounding":
        return engine.grounding(txt, ans)
    if ep == "compare":
        return engine.compare(txt, sec)
    if ep == "rerank":
        return engine.rerank(txt[:160], scen["passages"])
    return engine.pipeline(scenario_id=req.scenario_id, custom_input=req.input_text)


@app.post("/api/mcp")
def run_mcp(payload: Dict[str, Any]) -> Dict[str, Any]:
    return handle_mcp_request(payload, engine)


if PUBLIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(PUBLIC_DIR), html=True), name="public")
