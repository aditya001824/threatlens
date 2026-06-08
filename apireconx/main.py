from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from apireconx import __version__
from apireconx.config import get_settings
from apireconx.routers import discovery, graph, jwt, replay, reports, scans


settings = get_settings()

app = FastAPI(
    title="APIRECON-X",
    version=__version__,
    description="Authorized API attack surface discovery and security validation platform.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(discovery.router)
app.include_router(jwt.router)
app.include_router(scans.router)
app.include_router(replay.router)
app.include_router(graph.router)
app.include_router(reports.router)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/")
def root():
    index_path = _frontend_index()
    if index_path:
        return FileResponse(index_path)
    return {"name": "APIRECON-X", "docs": "/docs", "health": "/api/health"}


def _frontend_index() -> Path | None:
    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    index_path = dist / "index.html"
    return index_path if index_path.exists() else None


frontend_dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if frontend_dist.exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        index_path = _frontend_index()
        if not index_path:
            raise HTTPException(status_code=404, detail="Frontend build not found")
        return FileResponse(index_path)
