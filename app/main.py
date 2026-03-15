import os
import uuid
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from enum import Enum
from crewai import Crew, Process
from langchain_groq import ChatGroq

# ── Agents ────────────────────────────────────────────────────────────────────
from agents.detection_agent import detection_agent
from agents.threat_analyst import threat_analyst
from agents.vulnerability_researcher import vulnerability_researcher
from agents.incident_advisor import incident_response_advisor
from agents.report_writer import cybersecurity_writer
from agents.risk_scorer import risk_scorer

# ── Tasks ─────────────────────────────────────────────────────────────────────
from tasks.detection_task import detection_task
from tasks.threat_tasks import threat_analysis_task
from tasks.vulnerability_tasks import vulnerability_research_task
from tasks.incident_tasks import incident_response_task
from tasks.report_tasks import write_threat_report_task
from tasks.risk_tasks import risk_scoring_task

from config import GROQ_API_KEY, MODEL_NAME, OUTPUTS_DIR
from logger import get_logger

logger = get_logger(__name__)
os.environ["GROQ_API_KEY"] = GROQ_API_KEY

app = FastAPI(
    title="Multi-Agent Cybersecurity Intelligence System",
    description=(
        "A 6-agent CrewAI system with two operational modes: "
        "DETECT (monitor cloud server + auto-escalate to intelligence pipeline) "
        "and RESEARCH (standalone threat intelligence on a given query)."
    ),
    version="2.0.0"
)

# In-memory job store — swap with Redis for real production
jobs: dict = {}


# ── Request Models ────────────────────────────────────────────────────────────

class RunMode(str, Enum):
    detect   = "detect"    # Phase 1: scan server → Phase 2: intelligence (if threats found)
    research = "research"  # Phase 2 only: standalone intelligence research


class CrewRequest(BaseModel):
    mode: RunMode = RunMode.detect
    query: str = "latest cybersecurity threats 2024"
    log_paths: str = "/var/log/auth.log,/var/log/syslog"
    scan_hours: int = 24


# ── Crew Builders ─────────────────────────────────────────────────────────────

def build_detection_crew() -> Crew:
    """Phase 1: single-agent detection crew."""
    return Crew(
        agents=[detection_agent],
        tasks=[detection_task],
        process=Process.sequential,
        verbose=2,
        full_output=True,
    )


def build_intelligence_crew() -> Crew:
    """Phase 2: 5-agent hierarchical intelligence pipeline."""
    llm = ChatGroq(temperature=0, model_name=MODEL_NAME)
    return Crew(
        agents=[
            threat_analyst,
            vulnerability_researcher,
            incident_response_advisor,
            cybersecurity_writer,
            risk_scorer,
        ],
        tasks=[
            threat_analysis_task,
            vulnerability_research_task,
            incident_response_task,
            write_threat_report_task,
            risk_scoring_task,
        ],
        process=Process.hierarchical,
        manager_llm=llm,
        verbose=2,
        full_output=True,
        memory=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _no_threats_found(detection_output: str) -> bool:
    """Return True if detection output contains no actionable findings."""
    lowered = detection_output.lower()
    return (
        "total_threat_types_found: 0" in lowered
        and "total_network_threats: 0" in lowered
        and "total_fs_threats: 0" in lowered
    ) or "no threats detected" in lowered


def _save_report(job_id: str, content: str, prefix: str = "report") -> str:
    """Persist a report as a timestamped markdown file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"{prefix}_{timestamp}_{job_id[:8]}.md"
    path      = os.path.join(OUTPUTS_DIR, filename)
    with open(path, "w") as f:
        f.write(f"# Cybersecurity Intelligence Report\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Job ID:** `{job_id}`\n\n")
        f.write(content)
    logger.info(f"Report saved → {path}")
    return path


# ── Background Job Runners ────────────────────────────────────────────────────

def run_detect_mode(job_id: str, request: CrewRequest):
    """
    Two-phase execution:
      Phase 1 → Detection crew: logs + network + filesystem
      Phase 2 → If threats found: escalate to intelligence crew
               → If clean: complete with clean status (no wasteful LLM calls)
    """
    logger.info(f"[{job_id}] DETECT mode started")
    jobs[job_id].update({"status": "running", "phase": "detection"})

    try:
        # ── Phase 1: Detection ─────────────────────────────────────────────
        detection_output = build_detection_crew().kickoff().get("final_output", "")
        detection_path   = _save_report(job_id, detection_output, prefix="detection")

        jobs[job_id].update({
            "detection_report": detection_output,
            "detection_report_file": detection_path,
        })
        logger.info(f"[{job_id}] Phase 1 complete")

        # ── Escalation Decision ────────────────────────────────────────────
        if _no_threats_found(detection_output):
            logger.info(f"[{job_id}] System clean — skipping intelligence pipeline")
            jobs[job_id].update({
                "status": "completed",
                "phase": "completed",
                "escalated": False,
                "result": detection_output,
                "summary": "System scan completed. No active threats detected.",
                "completed_at": datetime.now().isoformat(),
            })
            return

        # ── Phase 2: Intelligence Escalation ──────────────────────────────
        logger.info(f"[{job_id}] Threats detected — escalating to intelligence pipeline")
        jobs[job_id].update({"phase": "intelligence", "escalated": True})

        intel_output  = build_intelligence_crew().kickoff().get("final_output", "")
        combined      = (
            "## Phase 1 — Detection Report\n\n"
            f"{detection_output}\n\n"
            "---\n\n"
            "## Phase 2 — Threat Intelligence & Risk Analysis\n\n"
            f"{intel_output}"
        )
        report_path = _save_report(job_id, combined, prefix="full_report")

        jobs[job_id].update({
            "status": "completed",
            "phase": "completed",
            "result": combined,
            "intelligence_report": intel_output,
            "output_file": report_path,
            "completed_at": datetime.now().isoformat(),
        })
        logger.info(f"[{job_id}] DETECT mode completed")

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}")
        jobs[job_id].update({
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now().isoformat(),
        })


def run_research_mode(job_id: str, request: CrewRequest):
    """Standalone intelligence research — skips detection phase entirely."""
    logger.info(f"[{job_id}] RESEARCH mode started: {request.query}")
    jobs[job_id].update({"status": "running", "phase": "intelligence"})

    try:
        output      = build_intelligence_crew().kickoff().get("final_output", "No output.")
        report_path = _save_report(job_id, output, prefix="research")

        jobs[job_id].update({
            "status": "completed",
            "phase": "completed",
            "escalated": False,
            "result": output,
            "output_file": report_path,
            "completed_at": datetime.now().isoformat(),
        })
        logger.info(f"[{job_id}] RESEARCH mode completed")

    except Exception as e:
        logger.error(f"[{job_id}] Failed: {e}")
        jobs[job_id].update({
            "status": "failed",
            "error": str(e),
            "failed_at": datetime.now().isoformat(),
        })


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Multi-Agent Cybersecurity Intelligence System v2.0",
        "modes": {
            "detect":   "Scan cloud server → auto-escalate to intelligence pipeline if threats found",
            "research": "Standalone threat intelligence research on a given query",
        },
        "endpoints": {
            "POST /run":                "Submit a job",
            "GET  /results/{job_id}":  "Poll job status and results",
            "GET  /jobs":              "List all jobs",
            "DELETE /jobs":            "Clear job history (demo reset)",
        }
    }


@app.post("/run")
def run(request: CrewRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id":     job_id,
        "mode":       request.mode,
        "query":      request.query,
        "status":     "queued",
        "phase":      "queued",
        "escalated":  None,
        "created_at": datetime.now().isoformat(),
    }

    if request.mode == RunMode.detect:
        background_tasks.add_task(run_detect_mode, job_id, request)
    else:
        background_tasks.add_task(run_research_mode, job_id, request)

    logger.info(f"Job {job_id} queued in {request.mode} mode")
    return {"job_id": job_id, "mode": request.mode, "status": "queued"}


@app.get("/results/{job_id}")
def get_results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found.")
    return jobs[job_id]


@app.get("/jobs")
def list_jobs():
    summary = [
        {
            "job_id":       j["job_id"],
            "mode":         j.get("mode"),
            "status":       j.get("status"),
            "phase":        j.get("phase"),
            "escalated":    j.get("escalated"),
            "created_at":   j.get("created_at"),
            "completed_at": j.get("completed_at"),
        }
        for j in jobs.values()
    ]
    return {
        "total": len(summary),
        "jobs": sorted(summary, key=lambda x: x["created_at"], reverse=True),
    }


@app.delete("/jobs")
def clear_jobs():
    jobs.clear()
    return {"message": "All jobs cleared."}
