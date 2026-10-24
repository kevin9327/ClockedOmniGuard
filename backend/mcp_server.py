"""
ClockedOmniGuard — 10-Tool Model Context Protocol (MCP) JSON-RPC 2.0 Server
Exposes all 10 Clocked endpoints across Group 1, Group 2, Group 3, and Pipeline to AI Agents.
"""

from __future__ import annotations

from typing import Any, Dict, List
from .clocked_engine import ClockedOmniEngine, PRESET_SCENARIOS


MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "clocked_decide",
        "group": "Group 1: Decide, Extract, or Fill",
        "endpoint": "POST /clocked/decide",
        "description": "Calibrated single-label or multi-label decision engine with class probabilities and abstention threshold.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_text": {"type": "string"},
                "labels": {"type": "array", "items": {"type": "string"}},
                "mode": {"type": "string", "enum": ["single_label", "multi_label"], "default": "single_label"},
            },
            "required": ["input_text"],
        },
    },
    {
        "name": "clocked_extract",
        "group": "Group 1: Decide, Extract, or Fill",
        "endpoint": "POST /clocked/extract",
        "description": "Extracts verbatim answer spans with exact character start/end offsets from source documents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "string"},
                "questions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, "question": {"type": "string"}},
                    },
                },
            },
            "required": ["context"],
        },
    },
    {
        "name": "clocked_fill",
        "group": "Group 1: Decide, Extract, or Fill",
        "endpoint": "POST /clocked/fill",
        "description": "Populates an entire structured record combining decide and extract fields in a single API admission.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "string"},
                "fields": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["context"],
        },
    },
    {
        "name": "clocked_pii",
        "group": "Group 2: Protect, Guard, or Inspect",
        "endpoint": "POST /clocked/pii",
        "description": "Detects and redacts/masks PII/PHI entities (EMAIL, PHONE, SSN, MRN, IBAN, DOB) with exact character offsets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_text": {"type": "string"},
                "action": {"type": "string", "enum": ["redact", "mask", "detect"], "default": "redact"},
            },
            "required": ["input_text"],
        },
    },
    {
        "name": "clocked_injection",
        "group": "Group 2: Protect, Guard, or Inspect",
        "endpoint": "POST /clocked/injection",
        "description": "Guards autonomous agents and RAG pipelines against prompt injection and instruction overrides with span evidence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_text": {"type": "string"},
                "sensitivity": {"type": "string", "enum": ["balanced", "strict"], "default": "strict"},
            },
            "required": ["input_text"],
        },
    },
    {
        "name": "clocked_script",
        "group": "Group 2: Protect, Guard, or Inspect",
        "endpoint": "POST /clocked/script",
        "description": "Inspects Bash, Python, and JS automation scripts for remote code execution, credential exfiltration, and log wiping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script_text": {"type": "string"},
                "language": {"type": "string", "enum": ["auto", "bash", "python", "javascript"], "default": "auto"},
            },
            "required": ["script_text"],
        },
    },
    {
        "name": "clocked_grounding",
        "group": "Group 3: Verify, Compare, or Rerank",
        "endpoint": "POST /clocked/grounding",
        "description": "Verifies AI-generated summaries sentence-by-sentence against source documents, pinpointing unsupported hallucinations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "context": {"type": "string"},
                "answer": {"type": "string"},
                "query": {"type": "string"},
            },
            "required": ["context", "answer"],
        },
    },
    {
        "name": "clocked_compare",
        "group": "Group 3: Verify, Compare, or Rerank",
        "endpoint": "POST /clocked/compare",
        "description": "Compares two document versions (e.g., MSA v2.4 vs Baseline v1.0) and highlights exact conflicting spans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_a": {"type": "string"},
                "document_b": {"type": "string"},
            },
            "required": ["document_a", "document_b"],
        },
    },
    {
        "name": "clocked_rerank",
        "group": "Group 3: Verify, Compare, or Rerank",
        "endpoint": "POST /clocked/rerank",
        "description": "Reranks up to 256 retrieval passages and assigns actionable triage labels (`use`, `expand`, `skip`).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "passages": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["query", "passages"],
        },
    },
    {
        "name": "clocked_pipeline",
        "group": "10th Endpoint: Single-Admission Chained Pipeline",
        "endpoint": "POST /clocked/pipeline",
        "description": "Chains Guard, Inspect, Protect, Extract, Decide, Fill, Rerank, Compare, and Verify in one admission with `stop: true` short-circuiting.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scenario_id": {"type": "string", "default": "scenario-enterprise-msa"},
                "stop_on_security_threat": {"type": "boolean", "default": True},
            },
        },
    },
]


def handle_mcp_request(payload: Dict[str, Any], engine: ClockedOmniEngine) -> Dict[str, Any]:
    req_id = payload.get("id", 1)
    method = payload.get("method", "tools/list")
    params = payload.get("params") or {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "server": "clocked-omniguard-mcp",
                "version": "1.0.0",
                "tools": MCP_TOOLS,
            },
        }

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        default_scen = PRESET_SCENARIOS[0]

        if name == "clocked_decide":
            out = engine.decide(args.get("input_text", default_scen["input_text"]), args.get("labels"), args.get("mode", "single_label"))
        elif name == "clocked_extract":
            out = engine.extract(args.get("context", default_scen["input_text"]), args.get("questions"))
        elif name == "clocked_fill":
            out = engine.fill(args.get("context", default_scen["input_text"]), args.get("fields"))
        elif name == "clocked_pii":
            out = engine.pii(args.get("input_text", default_scen["input_text"]), args.get("action", "redact"))
        elif name == "clocked_injection":
            out = engine.injection(args.get("input_text", default_scen["input_text"]), args.get("sensitivity", "strict"))
        elif name == "clocked_script":
            out = engine.script(args.get("script_text", default_scen["vendor_script"]), args.get("language", "auto"))
        elif name == "clocked_grounding":
            out = engine.grounding(
                args.get("context", default_scen["input_text"]),
                args.get("answer", default_scen["ai_draft_summary"]),
                args.get("query", "Summarize key obligations and terms"),
            )
        elif name == "clocked_compare":
            out = engine.compare(
                args.get("document_a", default_scen["input_text"]),
                args.get("document_b", default_scen["baseline_contract_v1"]),
            )
        elif name == "clocked_rerank":
            out = engine.rerank(
                args.get("query", default_scen["input_text"][:140]),
                args.get("passages", default_scen["passages"]),
            )
        elif name == "clocked_pipeline":
            out = engine.pipeline(
                args.get("scenario_id", "scenario-enterprise-msa"),
                args.get("custom_input"),
                args.get("stop_on_security_threat", True),
            )
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown Clocked MCP tool: {name}"},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tool": name,
                "content": [{"type": "json", "data": out}],
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unsupported MCP method: {method}"},
    }
