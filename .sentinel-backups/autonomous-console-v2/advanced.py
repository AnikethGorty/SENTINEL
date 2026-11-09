import asyncio
import json
import logging
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.models.advanced import ReportDraft, AutonomousSession
from app.models.project import Project, Transcript
from app.services.scope_gate import authorize_action, ScopeDenied
from app.services.scanner_client import submit_job
from app.services.execution_signing import sign_autonomous_execution_authorization
from app.services.vulnerability_intel import enrich_services
from app.api.assessment import parse_nmap_xml
from app.intelligence.providers.factory import get_ai_provider
from app.intelligence.providers.base import AIProviderUnavailable

logger = logging.getLogger("sentinel.advanced")
router = APIRouter(tags=["CPE Enrichment, Reports & Autonomous Assessment"])


class CPECompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criteria: str = Field(min_length=1, max_length=1024)
    observed: str = Field(min_length=1, max_length=1024)

@router.post("/assessment/cpe/compare")
def compare_cpe(request: CPECompareRequest):
    """Explicitly invoke the CPE 2.3 matcher for one criterion/observation pair."""
    from app.intelligence.vulnerability.cpe_matcher import compare_cpes, CPEParseError
    try:
        result = compare_cpes(request.criteria, request.observed)
        return {
            "matcher": "cpe_matcher",
            "criteria": request.criteria,
            "observed": request.observed,
            "relation": result["relation"].value if hasattr(result["relation"], "value") else str(result["relation"]),
            "compatible": result["compatible"],
            "attributes": {k: str(v) for k, v in result["attributes"].items()},
            "warning": "CPE compatibility is not proof of vulnerability. Version ranges and environmental prerequisites require separate evaluation."
        }
    except CPEParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
_tasks: dict[str, asyncio.Task] = {}

class EnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nmap_xml: str | None = None
    services: list[dict[str, Any]] = Field(default_factory=list, max_length=500)

@router.post("/assessment/enrich")
async def enrich_assessment(request: EnrichRequest):
    """Explicitly invoke deterministic CVE/CPE-related enrichment; never automatic."""
    if request.nmap_xml:
        try:
            services = parse_nmap_xml(request.nmap_xml)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid Nmap XML: {exc}") from exc
    else:
        services = request.services
    if not services:
        raise HTTPException(status_code=422, detail="Provide Nmap XML or a non-empty services array.")
    enriched = await enrich_services(services)
    return {
        "enrichment": "manual",
        "engine": "sentinel-vulnerability-intel-v0.1",
        "service_count": len(enriched),
        "candidate_count": sum(len(s.get("cve_candidates", [])) for s in enriched),
        "services": enriched,
        "limitations": [
            "This is a deterministic curated CVE profile evaluator, not complete NVD CPE applicability evaluation.",
            "A candidate is not proof of exploitability or a confirmed vulnerability.",
            "Configuration, platform, provenance and package-source prerequisites may remain unresolved."
        ]
    }

class ReportDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    transcript_id: str
    title: str = Field(default="SENTINEL Vulnerability Assessment Report", max_length=240)
    target: str = Field(default="Not specified", max_length=2048)
    scope_summary: str = Field(default="See approved project scope.", max_length=4000)
    services: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    executive_summary: str = Field(default="", max_length=12000)
    limitations: list[str] = Field(default_factory=list, max_length=100)

class ComponentDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str
    edited_content: str | None = None
    reviewed_by: str = Field(min_length=1, max_length=120)

class ApproveReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved_by: str = Field(min_length=1, max_length=120)

def _report_dict(row: ReportDraft):
    return {
        "id": row.id, "project_id": row.project_id, "transcript_id": row.transcript_id,
        "title": row.title, "status": row.status, "components": row.components,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "created_at": row.created_at.isoformat()
    }

@router.post("/reports/drafts")
def create_report_draft(request: ReportDraftRequest, db: Session = Depends(get_db)):
    project = db.get(Project, request.project_id)
    transcript = db.get(Transcript, request.transcript_id)
    if not project or not transcript or transcript.project_id != project.id:
        raise HTTPException(status_code=404, detail="Project or transcript not found.")
    components = [
        {"id": str(uuid.uuid4()), "kind": "executive_summary", "title": "Executive Summary",
         "content": request.executive_summary or f"Assessment of {request.target}. Review the findings and limitations below before drawing conclusions.",
         "status": "PENDING", "evidence": []},
        {"id": str(uuid.uuid4()), "kind": "scope", "title": "Scope & Methodology",
         "content": f"Target: {request.target}\nAuthorized scope: {request.scope_summary}\nMethodology: evidence-led service discovery and vulnerability intelligence enrichment.",
         "status": "PENDING", "evidence": []},
    ]
    for service in request.services:
        candidates = service.get("cve_candidates") or []
        base_title = f"{service.get('product') or service.get('name') or 'Service'} on {service.get('host') or request.target}:{service.get('port','?')}"
        if candidates:
            for candidate in candidates:
                cve_id = candidate.get("cve_id", "Unassigned CVE")
                finding_evidence = [{"source": "Nmap service observation", "service": service}]
                points = [
                    ("finding_title", f"{cve_id} — {base_title}", f"Proposed finding title: {cve_id} affecting {base_title}. Confirm the title accurately describes the issue before approval."),
                    ("affected_asset", f"{cve_id} — Affected asset", f"Asset: {service.get('host') or request.target}\nService: {service.get('name') or 'unknown'}\nPort/protocol: {service.get('port','?')}/{service.get('protocol') or 'tcp'}\nProduct/version: {service.get('product') or 'unknown'} {service.get('version') or 'unknown'}"),
                    ("classification", f"{cve_id} — Classification & applicability", f"CVSS/severity: Not independently established by this enrichment.\nApplicability status: {candidate.get('status')}\nConfidence: {candidate.get('confidence')}\nReason: {candidate.get('reason')}\nMissing evidence: {', '.join(candidate.get('missing_evidence') or []) or 'None recorded'}"),
                    ("technical_details", f"{cve_id} — Technical details", "Draft from observed service metadata only. Add validated technical details and root-cause analysis after manual verification. Do not infer exploitability from a version banner."),
                    ("reproduction", f"{cve_id} — Reproduction / proof of concept", "No exploit or injection test was performed by the scan-only enrichment workflow. Add safe, reproducible verification steps only if separately performed and authorized."),
                    ("impact", f"{cve_id} — Security impact", "Impact has not been established by the supplied service observation. Describe confidentiality, integrity and availability consequences only after verification."),
                    ("remediation", f"{cve_id} — Remediation", "Remediation requires review against the vendor advisory and the actual affected product/build/configuration. Add a verified vendor fix or mitigation before approval."),
                    ("references", f"{cve_id} — References", "Add authoritative vendor advisory and NVD references after validating the CVE-to-product mapping."),
                ]
                for kind, title, content in points:
                    components.append({
                        "id": str(uuid.uuid4()), "kind": kind, "title": title,
                        "content": content, "status": "PENDING", "severity": "UNASSESSED",
                        "evidence": finding_evidence, "cve": candidate
                    })
        else:
            components.append({
                "id": str(uuid.uuid4()), "kind": "observation", "title": base_title,
                "content": f"Observed service {service.get('name','unknown')} on port {service.get('port','?')}. Product/version: {service.get('product') or 'unknown'} {service.get('version') or ''}. No matching curated CVE candidate was returned.",
                "status": "PENDING", "severity": "INFORMATIONAL",
                "evidence": [{"source": "Nmap service observation", "service": service}]
            })
    components.append({
        "id": str(uuid.uuid4()), "kind": "limitations", "title": "Assessment Limitations",
        "content": "\n".join(request.limitations) if request.limitations else "Only the evidence supplied to the report composer is represented. Unperformed tests and unverified observations must not be treated as negative results.",
        "status": "PENDING", "evidence": []
    })
    row = ReportDraft(project_id=project.id, transcript_id=transcript.id, title=request.title,
                      status="DRAFT", components=components)
    db.add(row); db.commit(); db.refresh(row)
    return _report_dict(row)

@router.get("/reports/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    row = db.get(ReportDraft, report_id)
    if not row: raise HTTPException(status_code=404, detail="Report draft not found.")
    return _report_dict(row)

@router.post("/reports/{report_id}/components/{component_id}/decision")
def decide_report_component(report_id: str, component_id: str, request: ComponentDecision, db: Session = Depends(get_db)):
    row = db.scalar(select(ReportDraft).where(ReportDraft.id == report_id).with_for_update())
    if not row: raise HTTPException(status_code=404, detail="Report draft not found.")
    if row.status == "APPROVED": raise HTTPException(status_code=409, detail="Approved reports are immutable; create a new draft.")
    if request.decision not in {"ACCEPTED", "EDITED", "REMOVED", "PENDING"}:
        raise HTTPException(status_code=422, detail="Decision must be ACCEPTED, EDITED, REMOVED or PENDING.")
    components = list(row.components)
    component = next((c for c in components if c["id"] == component_id), None)
    if component is None: raise HTTPException(status_code=404, detail="Report component not found.")
    if request.decision == "EDITED":
        if request.edited_content is None or not request.edited_content.strip():
            raise HTTPException(status_code=422, detail="Edited content is required.")
        component["content"] = request.edited_content
    component["status"] = request.decision
    component["reviewed_by"] = request.reviewed_by
    component["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    row.components = components
    db.commit(); db.refresh(row)
    return _report_dict(row)

@router.post("/reports/{report_id}/approve")
def approve_report(report_id: str, request: ApproveReportRequest, db: Session = Depends(get_db)):
    row = db.scalar(select(ReportDraft).where(ReportDraft.id == report_id).with_for_update())
    if not row: raise HTTPException(status_code=404, detail="Report draft not found.")
    if row.status == "APPROVED": return _report_dict(row)
    pending = [c["title"] for c in row.components if c.get("status") == "PENDING"]
    if pending:
        raise HTTPException(status_code=409, detail={"message": "Every report component must be reviewed before final approval.", "pending": pending})
    if not any(c.get("status") in {"ACCEPTED", "EDITED"} for c in row.components):
        raise HTTPException(status_code=409, detail="The report has no included components.")
    row.status = "APPROVED"; row.approved_by = request.approved_by
    row.approved_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(row)
    return _report_dict(row)

@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    row = db.get(ReportDraft, report_id)
    if not row: raise HTTPException(status_code=404, detail="Report not found.")
    if row.status != "APPROVED": raise HTTPException(status_code=409, detail="Only a human-approved report can be downloaded as final.")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
        from reportlab.lib.units import mm
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib import colors
        from io import BytesIO
        from xml.sax.saxutils import escape
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm, topMargin=18*mm, bottomMargin=18*mm)
        styles = getSampleStyleSheet()
        story = [Paragraph("SENTINEL", styles["Title"]), Paragraph(escape(row.title), styles["Heading1"]),
                 Paragraph(f"Report ID: {row.id} · Status: HUMAN APPROVED", styles["Normal"]), Spacer(1, 12)]
        for comp in row.components:
            if comp.get("status") not in {"ACCEPTED", "EDITED"}: continue
            story.append(Paragraph(escape(comp.get("title","Section")), styles["Heading2"]))
            for para in str(comp.get("content","")).splitlines():
                if para.strip(): story.append(Paragraph(escape(para), styles["BodyText"]))
                else: story.append(Spacer(1, 5))
            ev = comp.get("evidence") or []
            if ev: story.append(Paragraph("Evidence references: " + escape(json.dumps(ev, default=str)[:3000]), styles["Italic"]))
            story.append(Spacer(1, 10))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Approved by {escape(row.approved_by or 'operator')} at {escape(row.approved_at.isoformat() if row.approved_at else '')}.", styles["Italic"]))
        doc.build(story)
        payload = buf.getvalue()
        return Response(content=payload, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="sentinel-report-{row.id}.pdf"'})
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="PDF renderer unavailable. Install reportlab in the backend image.") from exc

class AutonomousStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    transcript_id: str
    target: str = Field(min_length=1, max_length=2048)
    started_by: str = Field(default="operator", min_length=1, max_length=120)
    ports: list[int] = Field(default_factory=lambda: [21,22,80,443,8009,8180], min_length=1, max_length=100)

def _append_session_event(db, session, kind, message, data=None):
    events = list(session.events or [])
    events.append({"id": str(uuid.uuid4()), "at": datetime.now(timezone.utc).isoformat(),
                   "type": kind, "message": message, "data": data or {}})
    session.events = events[-250:]
    db.commit()

def _auto_sign_and_submit(db, session, tool, action, parameters):
    # GATE is invoked for every individual operation; session start is not a scope bypass.
    authorization = authorize_action(db, project_id=session.project_id,
        transcript_id=session.transcript_id, target=session.target, tool=tool,
        action=action, parameters=parameters, requested_by=f"autonomous-session:{session.id}")
    job_id = str(uuid.uuid4())
    job = {"job_id": job_id, "tool": tool, "action": action,
           "target": session.target, "parameters": parameters}
    token = sign_autonomous_execution_authorization(
        job_id=job_id, session_id=session.id, project_id=session.project_id,
        transcript_id=session.transcript_id, scope_revision_id=authorization.scope_revision_id,
        execution_id=authorization.execution_id, tool=tool, action=action,
        target=session.target, parameters=parameters)
    return job, authorization, token

async def _run_autonomous(session_id: str):
    db = SessionLocal()
    provider = None
    try:
        session = db.get(AutonomousSession, session_id)
        if not session: return
        session.status = "RUNNING"; db.commit()
        _append_session_event(db, session, "started", "Autonomous scan-only session started by the human operator.")
        # Initial service discovery is deliberately restricted to the scanner's non-approval Nmap capability.
        if session.stop_requested: return
        initial_ports = session.ports[:max(1, (len(session.ports) + 1) // 2)]
        params = {"ports": initial_ports, "excluded_ports": []}
        job, auth, token = _auto_sign_and_submit(db, session, "nmap", "service_discovery", params)
        _append_session_event(db, session, "scan_started", "Nmap service discovery started.", {"tool":"nmap","ports":session.ports})
        result = await submit_job(job, auth, token)
        scanner_result = result.get("result", {})
        session.results = list(session.results or []) + [{"tool":"nmap","result":scanner_result}]
        db.commit()
        _append_session_event(db, session, "scan_completed", "Nmap service discovery completed.", {"exit_code":scanner_result.get("exit_code")})
        xml = scanner_result.get("stdout", "")
        try: services = parse_nmap_xml(xml) if xml else []
        except Exception: services = []
        web_services = [s for s in services if s.get("port") in {80,443,8000,8080,8180,8443,8888}]
        # Gemini proposes follow-up Nmap scans only. Every proposed port is
        # checked against the human-approved initial port set and deduplicated.
        completed_ports = set(initial_ports)
        # A bounded loop prevents an unbounded autonomous process.
        for iteration in range(3):
            db.refresh(session)
            if session.stop_requested:
                break
            provider = None
            try:
                provider = get_ai_provider()
                prompt = json.dumps({
                    "authorized_target": session.target,
                    "human_approved_ports": session.ports,
                    "initial_scan_result": scanner_result,
                    "completed_scans": [{"tool": item.get("tool"), "parameters": item.get("parameters")} for item in session.results],
                    "instruction": "Choose at most one useful follow-up Nmap TCP service discovery scan using only ports from the human-approved list. Do not repeat completed ports. If no useful scan remains, return an empty actions list."
                }, default=str)
                generated = await provider.generate(
                    prompt=prompt,
                    system_instruction=(
                        'Return JSON only: {"actions":[{"tool":"nmap","action":"service_discovery",'
                        '"target":"AUTHORIZED_TARGET","parameters":{"ports":[22],"excluded_ports":[]},'
                        '"reason":"..."}]}. Only Nmap TCP service discovery. No scripts, payloads, '
                        'exploitation, authentication attempts, UDP scans, aggressive timing or other tools.'
                    ),
                    max_output_tokens=1600)
                raw = (generated.get("text") or "").strip()
                if raw.startswith("```"):
                    raw = "\n".join(raw.splitlines()[1:-1]).strip()
                parsed_plan = json.loads(raw)
                actions = parsed_plan.get("actions", []) if isinstance(parsed_plan, dict) else []
            except Exception as exc:
                _append_session_event(db, session, "planner_limited",
                    "Gemini could not produce a valid follow-up plan; the session will finish safely.",
                    {"error": str(exc)[:300]})
                break
            finally:
                if provider:
                    await provider.close()
            if not actions:
                _append_session_event(db, session, "planner_complete",
                    "Gemini found no further justified scan-only action.")
                break
            action = actions[0]
            if action.get("tool") != "nmap" or action.get("action") != "service_discovery":
                _append_session_event(db, session, "blocked",
                    "Planner action rejected: autonomous mode permits Nmap service discovery only.",
                    {"action": action})
                break
            params = action.get("parameters")
            if not isinstance(params, dict) or set(params) - {"ports", "excluded_ports"}:
                _append_session_event(db, session, "blocked",
                    "Planner action rejected: invalid Nmap parameter contract.", {"action": action})
                break
            proposed_ports = params.get("ports", [])
            excluded = params.get("excluded_ports", [])
            if (not isinstance(proposed_ports, list) or not proposed_ports
                or any(type(p) is not int or p not in session.ports for p in proposed_ports)
                or any(type(p) is not int or p < 1 or p > 65535 for p in excluded)
                or not set(proposed_ports).isdisjoint(completed_ports)):
                _append_session_event(db, session, "blocked",
                    "Planner action rejected: ports must be approved, valid and not already scanned.",
                    {"parameters": params})
                break
            params = {"ports": proposed_ports, "excluded_ports": excluded}
            job, auth, token = _auto_sign_and_submit(db, session, "nmap", "service_discovery", params)
            _append_session_event(db, session, "scan_started",
                "Gemini-planned Nmap service discovery started.",
                {"ports": proposed_ports, "reason": str(action.get("reason", ""))[:500]})
            next_result = await submit_job(job, auth, token)
            next_scanner_result = next_result.get("result", {})
            session.results = list(session.results or []) + [{
                "tool": "nmap", "parameters": params, "result": next_scanner_result
            }]
            db.commit()
            completed_ports.update(proposed_ports)
            _append_session_event(db, session, "scan_completed",
                "Gemini-planned Nmap service discovery completed.",
                {"ports": proposed_ports, "exit_code": next_scanner_result.get("exit_code")})
        db.refresh(session)
        session.status = "STOPPED" if session.stop_requested else "COMPLETED"
        session.finished_at = datetime.now(timezone.utc); db.commit()
        _append_session_event(db, session, "finished", f"Autonomous session {session.status.lower()}.")
    except Exception as exc:
        logger.exception("Autonomous session %s failed", session_id)
        row = db.get(AutonomousSession, session_id)
        if row:
            row.status = "FAILED"; row.error = f"{type(exc).__name__}: {str(exc)[:1000]}"
            row.finished_at = datetime.now(timezone.utc); db.commit()
            _append_session_event(db, row, "error", "Autonomous session failed.", {"error":row.error})
    finally:
        if provider:
            try: await provider.close()
            except Exception: pass
        db.close()
        _tasks.pop(session_id, None)

@router.post("/autonomous/start")
async def start_autonomous(request: AutonomousStartRequest, db: Session = Depends(get_db)):
    project = db.get(Project, request.project_id); transcript = db.get(Transcript, request.transcript_id)
    if not project or not transcript or transcript.project_id != project.id:
        raise HTTPException(status_code=404, detail="Project or transcript not found.")
    if any(not isinstance(p,int) or p < 1 or p > 65535 for p in request.ports):
        raise HTTPException(status_code=422, detail="Ports must be integers between 1 and 65535.")
    row = AutonomousSession(project_id=project.id, transcript_id=transcript.id,
        target=request.target, ports=request.ports, status="STARTING", events=[], results=[])
    db.add(row); db.commit(); db.refresh(row)
    task = asyncio.create_task(_run_autonomous(row.id))
    _tasks[row.id] = task
    return {"id":row.id,"status":row.status,"message":"Started scan-only autonomous assessment. Nmap TCP service discovery only; GATE revalidates every operation."}

@router.get("/autonomous/{session_id}")
def get_autonomous(session_id: str, db: Session = Depends(get_db)):
    row = db.get(AutonomousSession, session_id)
    if not row: raise HTTPException(status_code=404, detail="Autonomous session not found.")
    return {"id":row.id,"status":row.status,"target":row.target,"ports":row.ports,
            "events":row.events,"results":row.results,"error":row.error,
            "stop_requested":row.stop_requested,
            "created_at":row.created_at.isoformat(),
            "finished_at":row.finished_at.isoformat() if row.finished_at else None}

@router.post("/autonomous/{session_id}/stop")
def stop_autonomous(session_id: str, db: Session = Depends(get_db)):
    row = db.get(AutonomousSession, session_id)
    if not row: raise HTTPException(status_code=404, detail="Autonomous session not found.")
    if row.status in {"COMPLETED","FAILED","STOPPED"}: return {"id":row.id,"status":row.status}
    row.stop_requested = True; row.status = "STOP_REQUESTED"; db.commit()
    _append_session_event(db, row, "stop_requested", "Operator requested stop. The current scanner subprocess may finish; no subsequent operation will be started.")
    return {"id":row.id,"status":row.status,"message":"Stop requested; current in-flight scanner call is allowed to finish, then no further scans will run."}
