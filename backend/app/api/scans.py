import asyncio, json, uuid
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import select
from ..database import SessionLocal
from ..models.entities import Scan, Finding, Page, RequestRecord
from ..models.schemas import ScanCreate, FindingUpdate
from ..scanner.engine import ScannerEngine
from ..services.reporting import pdf_report, json_report, csv_report
from ..config import settings

router=APIRouter(prefix="/api")
EVENTS={}; TASKS={}
def scan_dict(s): return {"id":s.id,"target":s.target,"status":s.status,"created_at":s.created_at.isoformat(),"completed_at":s.completed_at.isoformat() if s.completed_at else None,"security_score":s.security_score,"duration":s.duration,"pages_scanned":s.pages_scanned,"requests_sent":s.requests_sent,"error":s.error}
def find_dict(f): return {c:getattr(f,c) for c in ["id","scan_id","title","severity","confidence","category","url","parameter","method","description","evidence","impact","detection","recommendation","owasp","cwe","status","reviewer_note"]}
async def launch(scan_id, config, demo=False):
    q=EVENTS.setdefault(scan_id,asyncio.Queue())
    async def emit(ev): await q.put(ev)
    db=SessionLocal()
    try: await ScannerEngine(db,scan_id,config,emit,demo).run()
    finally: db.close()
@router.post("/scans")
async def create_scan(req: ScanCreate):
    if not req.authorized: raise HTTPException(400,"Authorization confirmation is required")
    sid="WG-SCAN-"+uuid.uuid4().hex[:8].upper(); cfg=req.model_dump(); cfg["target"]=str(req.target)
    db=SessionLocal(); db.add(Scan(id=sid,target=str(req.target),config_json=json.dumps(cfg))); db.commit(); db.close(); EVENTS[sid]=asyncio.Queue(); TASKS[sid]=asyncio.create_task(launch(sid,cfg)); return {"scan_id":sid,"status":"queued"}
@router.post("/scans/demo")
async def demo_scan():
    sid="WG-DEMO-"+uuid.uuid4().hex[:8].upper(); cfg={"target":settings.demo_lab_url,"max_pages":25,"max_depth":2,"concurrency":3,"follow_redirects":True,"scan_javascript":True,"analyze_forms":True,"passive_only":False}
    db=SessionLocal(); db.add(Scan(id=sid,target="Bundled Local Security Lab",config_json=json.dumps(cfg))); db.commit(); db.close(); EVENTS[sid]=asyncio.Queue(); TASKS[sid]=asyncio.create_task(launch(sid,cfg,True)); return {"scan_id":sid,"status":"queued"}
@router.get("/scans")
def list_scans():
    db=SessionLocal(); data=[scan_dict(s) for s in db.execute(select(Scan).order_by(Scan.created_at.desc())).scalars()]; db.close(); return data
@router.get("/scans/{sid}")
def get_scan(sid:str):
    db=SessionLocal(); s=db.get(Scan,sid); 
    if not s: db.close(); raise HTTPException(404,"Scan not found")
    d=scan_dict(s); db.close(); return d
@router.get("/scans/{sid}/findings")
def findings(sid:str):
    db=SessionLocal(); d=[find_dict(f) for f in db.execute(select(Finding).where(Finding.scan_id==sid)).scalars()]; db.close(); return d
@router.patch("/findings/{fid}")
def update_finding(fid:str, req:FindingUpdate):
    db=SessionLocal(); f=db.get(Finding,fid)
    if not f: db.close(); raise HTTPException(404,"Finding not found")
    if req.status is not None:
        if req.status not in {"Open","Reviewed","False Positive","Accepted Risk","Fixed"}: raise HTTPException(400,"Invalid status")
        f.status=req.status
    if req.reviewer_note is not None:f.reviewer_note=req.reviewer_note[:4000]
    db.commit(); d=find_dict(f); db.close(); return d
@router.get("/scans/{sid}/pages")
def pages(sid:str):
    db=SessionLocal(); items=db.execute(select(Page).where(Page.scan_id==sid)).scalars(); d=[{c:getattr(x,c) for c in ["id","url","status_code","method","content_type","response_time","response_size","title","depth"]} for x in items]; db.close(); return d
@router.get("/scans/{sid}/requests")
def requests(sid:str):
    db=SessionLocal(); items=db.execute(select(RequestRecord).where(RequestRecord.scan_id==sid)).scalars(); d=[{c:getattr(x,c) for c in ["id","url","method","status_code","response_time","response_length","content_type","redirect_to","headers_json"]} for x in items]; db.close(); return d
@router.delete("/scans/{sid}")
def delete_scan(sid:str):
    t=TASKS.get(sid)
    if t and not t.done(): t.cancel()
    db=SessionLocal(); [db.delete(x) for cls in (Finding,Page,RequestRecord) for x in db.execute(select(cls).where(cls.scan_id==sid)).scalars()]; s=db.get(Scan,sid); 
    if s: db.delete(s)
    db.commit(); db.close(); return {"deleted":sid}
@router.get("/scans/{sid}/events")
async def events(sid:str):
    if sid not in EVENTS: EVENTS[sid]=asyncio.Queue()
    async def gen():
        while True:
            try: ev=await asyncio.wait_for(EVENTS[sid].get(),timeout=15); yield f"data: {json.dumps(ev)}\n\n"; 
            except asyncio.TimeoutError: yield ": keepalive\n\n"
            db=SessionLocal(); s=db.get(Scan,sid); terminal=s and s.status in {"completed","failed","cancelled"}; db.close()
            if terminal and EVENTS[sid].empty(): break
    return StreamingResponse(gen(),media_type="text/event-stream")
@router.get("/scans/{sid}/report/{fmt}")
def report(sid:str,fmt:str):
    db=SessionLocal(); s=db.get(Scan,sid); fs=list(db.execute(select(Finding).where(Finding.scan_id==sid)).scalars())
    if not s: db.close(); raise HTTPException(404,"Scan not found")
    if fmt=="pdf": content=pdf_report(s,fs); media="application/pdf"
    elif fmt=="json": content=json_report(s,fs).encode(); media="application/json"
    elif fmt=="csv": content=csv_report(fs).encode(); media="text/csv"
    else: db.close(); raise HTTPException(400,"Unsupported report format")
    db.close(); return Response(content,media_type=media,headers={"Content-Disposition":f'attachment; filename="{sid}.{fmt}"'})
