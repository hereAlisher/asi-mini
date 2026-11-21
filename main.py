from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from analyzer import analyze_scan
from scanner import SAMPLE_NMAP_XML, get_demo_scan, parse_nmap_xml, scan_domain

app = FastAPI(title="ASI Mini - CBI AGH")
app.mount("/static", StaticFiles(directory="static"), name="static")


class ImportPayload(BaseModel):
    filename: str = "internal-net.xml"
    content: str = ""
    sample: bool = False


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/scan")
async def scan(domain: str = Query("example.com"), demo: bool = Query(False)):
    raw = get_demo_scan(domain) if demo else await scan_domain(domain)
    return {**raw, **analyze_scan(raw)}


@app.post("/api/import")
async def import_nmap(payload: ImportPayload):
    try:
        xml_data = SAMPLE_NMAP_XML if payload.sample else payload.content
        raw = parse_nmap_xml(xml_data, payload.filename)
        return {**raw, **analyze_scan(raw)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
async def index():
    return FileResponse("static/index.html")