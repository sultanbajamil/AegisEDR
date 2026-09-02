import os
import json
import datetime
from fastapi import FastAPI, Depends, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import uuid

from database import init_db, get_db, Agent, Alert, Command

app = FastAPI(title="AegisEDR Management Server")

# Initialize database tables on startup
@app.on_event("startup")
def startup_event():
    init_db()

def check_virustotal(file_hash: str, file_path: str = "") -> dict | None:
    # 1. EICAR Test Mockup (Demo Mode)
    clean_path = (file_path or "").lower()
    if file_hash == "44d88612fea8a8f36de82e1278abb02f" or "eicar" in clean_path:
        return {
            "malicious": 62,
            "suspicious": 2,
            "harmless": 0,
            "undetected": 10,
            "total_engines": 74,
            "permalink": f"https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f"
        }
    
    # 2. Real VirusTotal API Lookup
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return None
        
    try:
        import urllib.request
        import urllib.error
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", vt_key)
        
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode())
            stats = res_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            if total > 0:
                return {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                }
    except Exception as e:
        print(f"[!] VirusTotal API lookup error: {e}")
        
    return None

# Templates configuration
templates_path = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_path)

# Helper function to mark inactive agents
def update_agent_statuses(db: Session):
    # If agent hasn't checked in for more than 30 seconds, mark as Inactive
    threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
    inactive_agents = db.query(Agent).filter(Agent.last_seen < threshold, Agent.status == "Active").all()
    for agent in inactive_agents:
        agent.status = "Inactive"
    db.commit()

# --- AGENT APIS ---

@app.post("/api/agent/register")
def register_agent(data: dict, db: Session = Depends(get_db)):
    agent_id = data.get("id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="Agent ID is required")
    
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        agent = Agent(
            id=agent_id,
            hostname=data.get("hostname", "Unknown"),
            ip_address=data.get("ip_address", "Unknown"),
            os_version=data.get("os_version", "Unknown"),
            status="Active",
            last_seen=datetime.datetime.utcnow()
        )
        db.add(agent)
    else:
        agent.hostname = data.get("hostname", agent.hostname)
        agent.ip_address = data.get("ip_address", agent.ip_address)
        agent.os_version = data.get("os_version", agent.os_version)
        agent.status = "Active"
        agent.last_seen = datetime.datetime.utcnow()
    
    db.commit()
    print(f"[*] Registered agent: {agent.hostname} ({agent_id})")
    return {"status": "success", "message": "Agent registered successfully"}

@app.post("/api/agent/heartbeat")
def agent_heartbeat(data: dict, db: Session = Depends(get_db)):
    agent_id = data.get("id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="Agent ID is required")
    
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        # If agent is checking in but not registered, register it implicitly
        agent = Agent(
            id=agent_id,
            hostname=data.get("hostname", "Unknown"),
            ip_address=data.get("ip_address", "Unknown"),
            os_version=data.get("os_version", "Unknown"),
            status="Active",
            last_seen=datetime.datetime.utcnow()
        )
        db.add(agent)
    else:
        agent.status = "Active"
        agent.last_seen = datetime.datetime.utcnow()
    
    db.commit()

    # Query any pending commands for this agent
    pending_commands = db.query(Command).filter(
        Command.agent_id == agent_id, 
        Command.status == "PENDING"
    ).all()

    commands_payload = []
    for cmd in pending_commands:
        commands_payload.append({
            "id": cmd.id,
            "command_type": cmd.command_type,
            "arguments": cmd.arguments
        })
        cmd.status = "SENT"
    
    db.commit()
    return {"status": "success", "commands": commands_payload}

@app.post("/api/agent/telemetry")
def receive_telemetry(data: dict, db: Session = Depends(get_db)):
    agent_id = data.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="Agent ID is required")
    
    # Check if agent exists
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    details = data.get("details", {})
    alert_type = data.get("alert_type", "INFO")
    severity = data.get("severity", "INFO")
    description = data.get("description", "")
    
    # VirusTotal Integration for File Alerts
    file_hash = details.get("file_hash")
    file_path = details.get("file_path", "")
    if file_hash and file_hash != "N/A (File deleted or inaccessible)" and not file_hash.startswith("Error"):
        vt_result = check_virustotal(file_hash, file_path)
        if vt_result:
            details["virustotal"] = vt_result
            malicious = vt_result["malicious"]
            if malicious > 0:
                severity = "CRITICAL" if malicious > 3 else "WARNING"
                description = f"[VirusTotal: {malicious}/{vt_result['total_engines']} Malicious] {description}"
    
    # Create Alert record
    details_str = json.dumps(details)
    alert = Alert(
        agent_id=agent_id,
        alert_type=alert_type,
        severity=severity,
        description=description,
        details=details_str,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(alert)
    db.commit()
    print(f"[!] Alert received from {agent.hostname}: {alert.description} ({alert.severity})")
    return {"status": "success"}

@app.post("/api/agent/command/result")
def command_result(data: dict, db: Session = Depends(get_db)):
    cmd_id = data.get("command_id")
    if not cmd_id:
        raise HTTPException(status_code=400, detail="Command ID is required")
    
    cmd = db.query(Command).filter(Command.id == cmd_id).first()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")
    
    cmd.status = data.get("status", "COMPLETED")
    cmd.result = data.get("result", "")
    cmd.executed_at = datetime.datetime.utcnow()
    
    db.commit()
    print(f"[*] Command {cmd_id} result received: {cmd.status} - {cmd.result}")
    return {"status": "success"}


# --- WEB DASHBOARD ROUTES ---

@app.get("/", response_class=HTMLResponse)
def index_page(request: Request, db: Session = Depends(get_db)):
    update_agent_statuses(db)
    # Sort agents: Active first
    agents = sorted(db.query(Agent).all(), key=lambda x: x.status == "Inactive")
    
    # Fetch alerts, order by timestamp desc
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
    
    # Deserialize details JSON for each alert to render in templates
    parsed_alerts = []
    for alert in alerts:
        details_obj = {}
        if alert.details:
            try:
                details_obj = json.loads(alert.details)
            except Exception:
                details_obj = {"raw": alert.details}
        parsed_alerts.append({
            "id": alert.id,
            "agent_hostname": alert.agent.hostname if alert.agent else "Unknown",
            "agent_id": alert.agent_id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "description": alert.description,
            "details": details_obj,
            "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": alert.resolved
        })

    # Fetch recent commands
    recent_commands = db.query(Command).order_by(Command.created_at.desc()).limit(10).all()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "agents": agents,
            "alerts": parsed_alerts,
            "commands": recent_commands
        }
    )

@app.post("/admin/command")
def queue_command(
    agent_id: str = Form(...),
    command_type: str = Form(...),
    arguments: str = Form(...),
    db: Session = Depends(get_db)
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    cmd_id = str(uuid.uuid4())
    cmd = Command(
        id=cmd_id,
        agent_id=agent_id,
        command_type=command_type,
        arguments=arguments,
        status="PENDING",
        created_at=datetime.datetime.utcnow()
    )
    db.add(cmd)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/admin/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/admin/alerts/clear")
def clear_all_alerts(db: Session = Depends(get_db)):
    db.query(Alert).delete()
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.post("/admin/agents/{agent_id}/delete")
def delete_agent(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    db.delete(agent)
    db.commit()
    return RedirectResponse(url="/", status_code=303)
