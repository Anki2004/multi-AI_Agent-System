#  Multi-Agent AI Cybersecurity Threat Intelligence System

> An AI-powered security system that watches your cloud server around the clock, detects attacks as they happen, and automatically writes a full investigation report — without any human needing to press a button.

---

## What Does This Project Do?

Imagine you own a shop and you hire six security guards. Each guard has a different job:

- **Guard 1** watches the entrance and checks if anyone is trying to break in
- **Guard 2** reads the news to find out what criminal tactics are trending
- **Guard 3** checks a government database of known criminal methods
- **Guard 4** decides what action to take based on what Guards 2 and 3 found
- **Guard 5** writes a full incident report
- **Guard 6** grades each threat from "minor concern" to "emergency"

This project does exactly that — but for a cloud server, using AI agents instead of human guards.

When an attack is detected, the system does not just raise an alarm. It automatically researches the attack, looks up known software weaknesses that the attacker may be exploiting, suggests specific actions to take, and produces a risk-scored report — all within minutes.

---

## The Problem It Solves

Every day, thousands of cyberattacks happen worldwide. The people whose job is to stop these attacks — called security analysts — face three major problems:

1. **Too much to read** — A busy server generates thousands of log entries every hour. No human can read all of these manually and spot an attack in time.

2. **AI tools that make things up** — Many AI security tools answer questions using information they were trained on months ago. They miss brand new attacks, and sometimes invent fake details when they do not know the real answer.

3. **Slow investigation** — Even when an attack is spotted, writing a proper investigation report with recommendations can take hours of manual work.

This system solves all three problems by automatically reading the server's logs, checking real live data sources, and writing the report itself.

---

## How It Works

The system runs in two phases:

### Phase 1 — Detection (Is anything wrong?)

A **Cloud Security Detection Agent** scans the server across three attack surfaces:

| What it scans | What it looks for |
|---|---|
| **Log files** | Failed login attempts, brute force attacks, root login, malware processes |
| **Network traffic** | Port scans, suspicious connections, backdoor ports open |
| **File system** | Web shells planted, system files modified, new SSH keys added, executables in /tmp |

If Phase 1 finds nothing suspicious → the job is marked **clean** and Phase 2 is skipped (saving resources).

If Phase 1 finds something → it automatically escalates to Phase 2.

### Phase 2 — Investigation (What happened and what do we do?)

Five specialized agents work in sequence:

```
Threat Analyst → Vulnerability Researcher → Incident Advisor → Report Writer → Risk Scorer
```

| Agent | Job |
|---|---|
| **Threat Intelligence Analyst** | Searches the internet in real time for news about the detected attack type |
| **Vulnerability Researcher** | Looks up real CVEs from the official NVD government database |
| **Incident Response Advisor** | Produces a prioritized action plan (Immediate / Short-term / Long-term) |
| **Report Writer** | Combines everything into a structured markdown report |
| **Risk Scorer** | Assigns severity, likelihood, and impact scores to every threat found |

---

## What Threats Can It Detect?

| Attack Phase | Detection Source | Threat Detected |
|---|---|---|
| Getting in | Log files | SSH brute force, password spraying |
| Getting in | Log files | Root login attempts |
| Getting in | Network | Port scanning from external IP |
| Running malware | Log files | Known malware tool names (netcat, mimikatz) |
| Hiding a backdoor | File system | Web shell planted in website folder |
| Staying persistent | File system | New SSH key added secretly |
| Staying persistent | File system | Critical system files modified (/etc/passwd, /etc/shadow) |
| Staying persistent | File system | New files with dangerous permissions (SUID binaries) |
| Gaining more access | Log files | Sudo failures, privilege escalation |
| Communicating with attacker | Network | High-frequency connections to same IP (C2 beaconing) |
| Opening a backdoor | Network | Known backdoor ports listening (4444, 1337, 31337) |

---

## Project Structure

```
multi-agent-cybersec/
│
├── agents/                       
│   ├── detection_agent.py         # Phase 1: scans server with all 3 tools
│   ├── threat_analyst.py          # Phase 2: searches internet for threat news
│   ├── vulnerability_researcher.py # Phase 2: fetches real CVEs from NVD
│   ├── incident_advisor.py        # Phase 2: produces action plan
│   ├── report_writer.py           # Phase 2: writes the full report
│   └── risk_scorer.py             # Phase 2: scores every threat
│
├── tasks/                        
│   ├── detection_task.py
│   ├── threat_tasks.py
│   ├── vulnerability_tasks.py
│   ├── incident_tasks.py
│   ├── report_tasks.py
│   └── risk_tasks.py
│
├── tools/                         # Real data tools the agents can use
│   ├── log_analysis_tool.py       # Reads server log files
│   ├── network_monitor_tool.py    # Checks network connections
│   ├── filesystem_monitor_tool.py # Scans server file system
│   ├── exa_tools.py               # Searches internet for threat news (Exa API)
│   └── nvd_tools.py               
│
├── app/
│   └── main.py                    
│
├── ui/
│   └── streamlit_app/
│       └── ui.py                  
│
├── tests/
│   └── test_filesystem_tool.py    
│
├── scripts/
│   └── generate_demo_logs.py      
│
├── outputs/                      
│
├── config.py                      # API keys and settings (loaded from .env)
├── logger.py                      # Structured logging
├── .env.example                   # Template for your API keys
├── requirements.txt               # Python packages needed
├── Dockerfile                     # Packages the app into a container
└── docker-compose.yml             # Runs both API and dashboard together
```

---

## Tech Stack

| Technology | What it does in this project |
|---|---|
| **CrewAI** | The framework that builds the team of AI agents and manages how they work together |
| **Groq + Llama3-70b** | The AI brain — fast language model that powers all six agents |
| **Exa API** | Real-time internet search — so agents get current threat news, not old training data |
| **NVD API** | Official US government database of software vulnerabilities — free, no key needed |
| **FastAPI** | The web backend that receives scan requests and runs them in the background |
| **Streamlit** | The web dashboard you see in your browser |
| **Docker** | Packages everything so it runs identically on any cloud server |
| **pytest** | Runs automated tests to verify the detection tools work correctly |

---

## Getting Started

### Prerequisites

- Python 3.11+
- A [Groq API key](https://console.groq.com) (free)
- An [Exa API key](https://exa.ai) (free tier available)
- Docker (optional, for deployment)

### Option A — Run Locally

**Step 1: Clone and set up environment**
```bash
git clone https://github.com/yourusername/multi-agent-cybersec.git
cd multi-agent-cybersec

python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

**Step 2: Add your API keys**
```bash
cp .env.example .env
# Open .env and fill in your GROQ_API_KEY and EXA_API_KEY
```

**Step 3: Start the backend API**
```bash
uvicorn app.main:app --reload
# API is now running at http://localhost:8000
```

**Step 4: Start the dashboard** (in a new terminal)
```bash
streamlit run ui/streamlit_app/ui.py
# Dashboard is now open at http://localhost:8501
```

### Option B — Run with Docker (Recommended for Cloud)

```bash
cp .env.example .env
# Fill in your API keys in .env

docker-compose up --build
# API  → http://localhost:8000
# UI   → http://localhost:8501
```

That's it. One command and the entire system is running.

---

## Running the Demo (Without a Real Server)

If you want to demo the detection phase without running on a real cloud server, use the demo log generator:

```bash
python scripts/generate_demo_logs.py
```

This creates realistic fake log files that simulate a complete attack chain:
1. Port scan from an attacker IP
2. 60 SSH brute force attempts
3. Successful root login
4. Privilege escalation attempt
5. Malware process execution (netcat)
6. Crontab modification for persistence

Then update the log paths in the Streamlit dashboard to point to the generated files.

---

## Using the Dashboard

Open `http://localhost:8501` in your browser.

**Detect Mode** — scans your cloud server:
1. Select "Detect — Scan Server" in the sidebar
2. Enter your log file paths (default: `/var/log/auth.log,/var/log/syslog`)
3. Set how many hours back to scan
4. Click **Run**
5. Watch Phase 1 and Phase 2 progress in real time
6. View detection findings, intelligence report, and risk matrix across the three tabs
7. Download the full report as a `.md` file

**Research Mode** — standalone threat intelligence:
1. Select "Research — Threat Intel" in the sidebar
2. Type a threat topic (e.g. "latest ransomware attacks 2024")
3. Click **Run** — skips detection and goes straight to the 5-agent pipeline

---

## Running the Tests

```bash
pytest tests/ -v
```

Current test coverage for `FileSystemMonitorTool`:

| Test | What it checks |
|---|---|
| `test_critical_file_modification` | Recently modified system file → alert raised |
| `test_critical_file_not_modified` | Old file not changed recently → no alert |
| `test_critical_file_not_found` | File does not exist → no crash, no alert |

Tests use temporary files and mocking — they never touch real system files like `/etc/passwd`.

---

## API Endpoints

Once the backend is running, you can also call it directly:

| Method | Endpoint | What it does |
|---|---|---|
| `GET` | `/` | Check if API is running |
| `POST` | `/run` | Submit a new scan or research job |
| `GET` | `/results/{job_id}` | Check the status and result of a job |
| `GET` | `/jobs` | List all past jobs |
| `DELETE` | `/jobs` | Clear all job history (useful for demos) |

Example — start a detect scan:
```bash
curl -X POST http://localhost:8000/run \
  -H "Content-Type: application/json" \
  -d '{"mode": "detect", "log_paths": "/var/log/auth.log,/var/log/syslog", "scan_hours": 24}'
```

---

## Two Operation Modes Explained

```
┌─────────────────────────────────────────────────────────┐
│                     User submits job                    │
└────────────────────────┬────────────────────────────────┘
                         │
           ┌─────────────▼──────────────┐
           │     Which mode?            │
           └──────┬──────────────┬──────┘
                  │              │
           DETECT mode     RESEARCH mode
                  │              │
    ┌─────────────▼──────┐       │
    │  Phase 1: Scan     │       │
    │  logs + network    │       │
    │  + filesystem      │       │
    └─────────┬──────────┘       │
              │                  │
    ┌─────────▼──────────┐       │
    │ Any threats found? │       │
    └──┬──────────────┬──┘       │
       │ NO           │ YES      │
       ▼              ▼          ▼
    Mark          Phase 2: 5-agent
    clean     intelligence pipeline
                       │
              ┌────────▼────────┐
              │  Final Report   │
              │  + Risk Matrix  │
              └─────────────────┘
```

---

## Environment Variables

Create a `.env` file in the root folder (copy from `.env.example`):

```
GROQ_API_KEY=your_groq_api_key_here
EXA_API_KEY=your_exa_api_key_here
MODEL_NAME=llama3-70b-8192
```

The NVD API requires no key — it is free and open.

---

## Known Limitations

- **Not a real-time continuous monitor** — the system runs on-demand scans, not a persistent always-on daemon. For continuous monitoring, you would schedule it as a cron job.
- **Log file access** — on a real cloud server, reading `/var/log/auth.log` requires appropriate permissions. Run with a user that has read access to log files.
- **Network monitoring** — the `ss` command used for network scanning is Linux-only. This tool will not work on Windows servers.
- **In-memory job store** — job history is stored in memory and lost if the API restarts. For production, replace with Redis or a database.

---

## Future Improvements

- Automatic email or SMS alerts when CRITICAL threats are detected
- Continuous monitoring mode that runs every 15 minutes via a scheduler
- Integration with industry threat feeds (MISP, STIX/TAXII)
- Persistent memory across sessions so the system recognizes repeat attackers
- Cloud-specific detection (unauthorized S3 bucket access, suspicious API calls)
- Tests for `LogAnalysisTool` and `NetworkMonitorTool`

---

## Project Context

Built as a Final Year Major Project for B.Tech in Information Technology at Maharaja Surajmal Institute of Technology, Delhi, submitted to Guru Gobind Singh Indraprastha University (GGSIPU).

---

## License

This project is for academic purposes.
