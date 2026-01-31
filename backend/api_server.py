"""
FastAPI server for AI-DLP System.
Provides REST API and WebSocket endpoints for DLP functionality.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# Import backend modules
from backend.database import (
    Alert,
    FileScan,
    Policy,
    create_alert,
    create_file_scan,
    create_policy,
    delete_policy,
    get_alerts,
    get_db,
    get_file_scans,
    get_policies,
    get_policy,
    get_stats,
    init_db,
    update_policy,
)
from backend.file_monitor import FileContentExtractor, FileMonitor, get_monitor
from backend.policy_manager import PolicyManager
from backend.redaction_engine import RedactionEngine

# Import existing DLP engine
from app.dlp_engine import decision_engine
from preprocessing.preprocess import normalize_text


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    print("✅ Database initialized")
    print("🚀 AI-DLP API Server running on http://localhost:8000")
    print("📚 API docs available at http://localhost:8000/docs")
    yield
    # Cleanup on shutdown
    monitor = get_monitor()
    if monitor.is_running:
        monitor.stop()
    print("👋 Server shutting down")


# Initialize FastAPI app
app = FastAPI(
    title="AI-DLP System API",
    description="Advanced Data Loss Prevention System with ML-assisted detection",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for request/response
class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="Text to analyze")
    policy_ids: Optional[List[int]] = Field(None, description="Policy IDs to apply")


class BatchAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., description="List of texts to analyze")
    policy_ids: Optional[List[int]] = Field(None, description="Policy IDs to apply")


class MonitorStartRequest(BaseModel):
    directory: str = Field(..., description="Directory path to monitor")
    recursive: bool = Field(True, description="Monitor subdirectories")
    scan_existing: bool = Field(True, description="Scan existing files")


class FileScanRequest(BaseModel):
    file_path: str = Field(..., description="File path to scan")


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., description="Policy name")
    description: Optional[str] = Field(None, description="Policy description")
    enabled: bool = Field(True, description="Whether policy is enabled")
    priority: int = Field(5, description="Policy priority (higher = applied first)")
    rules: Dict[str, Any] = Field(..., description="Policy rules")


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, description="Policy name")
    description: Optional[str] = Field(None, description="Policy description")
    enabled: Optional[bool] = Field(None, description="Whether policy is enabled")
    priority: Optional[int] = Field(None, description="Policy priority")
    rules: Optional[Dict[str, Any]] = Field(None, description="Policy rules")


class RedactRequest(BaseModel):
    text: str = Field(..., description="Text to redact")
    mode: str = Field("full", description="Redaction mode: full, partial, tokenize, hash")
    show_last: Optional[int] = Field(4, description="For partial mode: characters to show")
    placeholder: Optional[str] = Field("[REDACTED]", description="For full mode: placeholder text")


# WebSocket connection manager
class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


# Analysis Endpoints
@app.post("/api/analyze", tags=["Analysis"])
async def analyze_text(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analyze text for sensitive data.
    
    Returns DLP decision with classification, risk level, and action.
    """
    try:
        # Run DLP analysis
        result = decision_engine(request.text)
        
        # Apply policies if specified
        if request.policy_ids:
            policies = [get_policy(db, pid) for pid in request.policy_ids]
            policies = [p.to_dict() for p in policies if p and p.enabled]
            if policies:
                result = PolicyManager.apply_policies(policies, result)
        
        # Store in database
        result["source"] = "api"
        alert = create_alert(db, result)
        
        # Broadcast to WebSocket clients
        await manager.broadcast({
            "type": "new_alert",
            "data": alert.to_dict(),
        })
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/batch", tags=["Analysis"])
async def batch_analyze(request: BatchAnalyzeRequest, db: Session = Depends(get_db)):
    """Batch analyze multiple texts."""
    try:
        results = []
        for text in request.texts:
            result = decision_engine(text)
            
            # Apply policies
            if request.policy_ids:
                policies = [get_policy(db, pid) for pid in request.policy_ids]
                policies = [p.to_dict() for p in policies if p and p.enabled]
                if policies:
                    result = PolicyManager.apply_policies(policies, result)
            
            # Store in database
            result["source"] = "batch_api"
            create_alert(db, result)
            results.append(result)
        
        return {"results": results, "count": len(results)}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analyze/history", tags=["Analysis"])
async def get_analysis_history(
    skip: int = 0,
    limit: int = 100,
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Get analysis history with pagination."""
    try:
        alerts = get_alerts(db, skip=skip, limit=limit, risk_level=risk_level)
        return {"alerts": [a.to_dict() for a in alerts], "count": len(alerts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# File Monitoring Endpoints
@app.post("/api/monitor/start", tags=["File Monitoring"])
async def start_monitoring(request: MonitorStartRequest, db: Session = Depends(get_db)):
    """Start monitoring a directory."""
    try:
        monitor = get_monitor()
        
        # Define scan callback
        def scan_file(file_path: Path):
            content = FileContentExtractor.extract(file_path)
            if content:
                result = decision_engine(content)
                result["source"] = f"file:{file_path}"
                
                # Store alert
                create_alert(db, result)
                
                # Store file scan
                create_file_scan(db, {
                    "file_path": str(file_path),
                    "file_size": file_path.stat().st_size if file_path.exists() else 0,
                    "findings_count": 1 if result["risk_level"] != "LOW" else 0,
                    "highest_risk": result["risk_level"],
                    "status": "completed",
                })
                
                # Broadcast alert
                asyncio.create_task(manager.broadcast({
                    "type": "file_alert",
                    "data": {"file": str(file_path), "result": result},
                }))
        
        # Start monitoring
        monitor.start(request.directory, scan_file, recursive=request.recursive)
        
        # Scan existing files if requested
        if request.scan_existing:
            FileMonitor.scan_directory(request.directory, scan_file)
        
        return {
            "status": "started",
            "directory": request.directory,
            "recursive": request.recursive,
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/monitor/stop", tags=["File Monitoring"])
async def stop_monitoring():
    """Stop file monitoring."""
    try:
        monitor = get_monitor()
        monitor.stop()
        return {"status": "stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/monitor/status", tags=["File Monitoring"])
async def get_monitor_status():
    """Get current monitoring status."""
    try:
        monitor = get_monitor()
        return monitor.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/scan", tags=["File Monitoring"])
async def scan_file(request: FileScanRequest, db: Session = Depends(get_db)):
    """Scan a specific file."""
    try:
        file_path = Path(request.file_path)
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        content = FileContentExtractor.extract(file_path)
        if content is None:
            raise HTTPException(status_code=400, detail="Unsupported file type")
        
        result = decision_engine(content)
        result["source"] = f"file:{file_path}"
        
        # Store alert
        create_alert(db, result)
        
        # Store file scan
        scan = create_file_scan(db, {
            "file_path": str(file_path),
            "file_size": file_path.stat().st_size,
            "findings_count": 1 if result["risk_level"] != "LOW" else 0,
            "highest_risk": result["risk_level"],
            "status": "completed",
        })
        
        return {"scan": scan.to_dict(), "result": result}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/files/results", tags=["File Monitoring"])
async def get_file_results(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get file scan results."""
    try:
        scans = get_file_scans(db, skip=skip, limit=limit)
        return {"scans": [s.to_dict() for s in scans], "count": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/upload", tags=["File Monitoring"])
async def upload_and_scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload and scan a file."""
    try:
        # Create uploads directory if it doesn't exist
        upload_dir = Path("./uploads")
        upload_dir.mkdir(exist_ok=True)
        
        # Save uploaded file
        file_path = upload_dir / file.filename
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Extract and analyze content
        extracted_content = FileContentExtractor.extract(file_path)
        if extracted_content is None:
            raise HTTPException(status_code=400, detail="Unsupported file type or unable to extract content")
        
        result = decision_engine(extracted_content)
        result["source"] = f"upload:{file.filename}"
        
        # Store alert
        create_alert(db, result)
        
        # Store file scan
        scan = create_file_scan(db, {
            "file_path": str(file_path),
            "file_size": file_path.stat().st_size,
            "findings_count": 1 if result["risk_level"] != "LOW" else 0,
            "highest_risk": result["risk_level"],
            "status": "completed",
        })
        
        # Broadcast to WebSocket clients
        await manager.broadcast({
            "type": "file_upload",
            "data": {"filename": file.filename, "result": result},
        })
        
        return {
            "scan": scan.to_dict(),
            "result": result,
            "filename": file.filename,
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Policy Management Endpoints
@app.get("/api/policies", tags=["Policies"])
async def list_policies(enabled_only: bool = False, db: Session = Depends(get_db)):
    """List all policies."""
    try:
        policies = get_policies(db, enabled_only=enabled_only)
        return {"policies": [p.to_dict() for p in policies], "count": len(policies)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/policies", tags=["Policies"])
async def create_new_policy(request: PolicyCreateRequest, db: Session = Depends(get_db)):
    """Create a new policy."""
    try:
        # Validate policy
        policy_dict = request.dict()
        is_valid, error = PolicyManager.validate_policy(policy_dict)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)
        
        policy = create_policy(db, policy_dict)
        return policy.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/policies/templates", tags=["Policies"])
async def get_policy_templates():
    """Get compliance policy templates."""
    try:
        templates = PolicyManager.get_templates()
        return {"templates": templates}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/policies/{policy_id}", tags=["Policies"])
async def get_policy_by_id(policy_id: int, db: Session = Depends(get_db)):
    """Get a specific policy."""
    try:
        policy = get_policy(db, policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        return policy.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/policies/{policy_id}", tags=["Policies"])
async def update_policy_by_id(
    policy_id: int,
    request: PolicyUpdateRequest,
    db: Session = Depends(get_db),
):
    """Update a policy."""
    try:
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        policy = update_policy(db, policy_id, update_data)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        return policy.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/policies/{policy_id}", tags=["Policies"])
async def delete_policy_by_id(policy_id: int, db: Session = Depends(get_db)):
    """Delete a policy."""
    try:
        success = delete_policy(db, policy_id)
        if not success:
            raise HTTPException(status_code=404, detail="Policy not found")
        return {"status": "deleted", "policy_id": policy_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# Redaction Endpoints
@app.post("/api/redact", tags=["Redaction"])
async def redact_text(request: RedactRequest):
    """Redact sensitive data from text."""
    try:
        kwargs = {}
        if request.mode == "partial":
            kwargs["show_last"] = request.show_last
        elif request.mode == "full":
            kwargs["placeholder"] = request.placeholder
        
        result = RedactionEngine.redact(request.text, mode=request.mode, **kwargs)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/redaction/modes", tags=["Redaction"])
async def get_redaction_modes():
    """Get available redaction modes."""
    try:
        modes = RedactionEngine.get_available_modes()
        return {"modes": modes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Analytics Endpoints
@app.get("/api/analytics/stats", tags=["Analytics"])
async def get_analytics_stats(db: Session = Depends(get_db)):
    """Get overall statistics."""
    try:
        stats = get_stats(db)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/timeline", tags=["Analytics"])
async def get_timeline(limit: int = 50, db: Session = Depends(get_db)):
    """Get detection timeline."""
    try:
        alerts = get_alerts(db, skip=0, limit=limit)
        timeline = [
            {
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "risk_level": a.risk_level,
                "classification": a.classification,
                "source": a.source,
            }
            for a in alerts
        ]
        return {"timeline": timeline}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/risks", tags=["Analytics"])
async def get_risk_distribution(db: Session = Depends(get_db)):
    """Get risk level distribution."""
    try:
        stats = get_stats(db)
        return {
            "distribution": {
                "HIGH": stats["high_risk_alerts"],
                "MEDIUM": stats["medium_risk_alerts"],
                "LOW": stats["low_risk_alerts"],
            },
            "total": stats["total_alerts"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back for heartbeat
            await websocket.send_json({"type": "pong", "data": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Health check
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "2.0.0"}


# Run server
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
