# APIRECON-X

AI-powered API attack surface discovery, authorized security validation, attack-path analysis, and replayable attack simulation.

## Current MVP

- OpenAPI/Swagger import into an endpoint inventory
- Context-aware attack case generation from paths, parameters, and schemas
- Authorized scanner for broken auth, BOLA, excessive data exposure, mass assignment, SSRF-style URL probes, rate-limit checks, and business-logic boundaries
- JWT analyzer for weak secrets, alg issues, missing expiration, replay risk, and privilege-bearing claims
- SQLite-backed attack replay history
- Attack path graph API and React/D3 visualization
- Local intentionally vulnerable demo target

## Architecture

```text
apireconx/
  main.py                  FastAPI app
  demo_target.py           Local vulnerable API for safe testing
  storage.py               SQLite scan, finding, endpoint, and replay store
  services/
    openapi_importer.py    OpenAPI parsing
    attack_generator.py    Context-aware attack case generation
    scanner.py             Bounded authorized scanner and replay
    jwt_analyzer.py        JWT security analysis
    graph_builder.py       Attack path graph model
  routers/                 API routes

frontend/
  src/App.jsx              React console
  src/AttackGraph.jsx      D3 attack graph
```

## Quick Start

Start the full live demo with one command:

```powershell
.\scripts\start-apireconx.ps1
```

Open:

```text
http://127.0.0.1:5173
```

Stop the demo services:

```powershell
.\scripts\stop-apireconx.ps1
```

Manual setup is also available.

Create a virtual environment and install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the APIRECON-X backend:

```powershell
python -m uvicorn apireconx.main:app --reload --port 8000
```

Run the local demo target in another terminal:

```powershell
python -m uvicorn apireconx.demo_target:app --reload --port 9000
```

Run the React console:

```powershell
cd frontend
npm install
npm run dev
```

## Demo Flow

1. Start the backend on port `8000`.
2. Start the demo target on port `9000`.
3. Open the React console.
4. Import the sample OpenAPI spec from `samples/apireconx-demo-openapi.yaml` or use `http://127.0.0.1:9000/openapi.json`.
5. Run a scan against `http://127.0.0.1:9000` with `Authorization: Bearer user-1`.
6. Open the graph, replay, and reports tabs.

The scanner tab also includes a one-click `Demo Run` action that imports the local demo target and runs a bounded authorized scan.

## Single-Container Build

Build the APIRECON-X backend with the React app served by FastAPI:

```powershell
docker build -f Dockerfile.apireconx -t apireconx .
docker run -p 8000:8000 apireconx
```

Open:

```text
http://127.0.0.1:8000
```

Run the full container demo with backend and demo target:

```powershell
docker compose -f docker-compose.apireconx.yml up --build
```

## Safety Boundary

APIRECON-X is built for owned systems, local labs, staging environments, and explicitly authorized assessments. The scanner requires `authorized=true` before it sends or replays requests.

## Resume Pitch

Built an AI-powered autonomous API security assessment platform that discovers API attack surfaces, generates context-aware fuzzing tests, validates OWASP API Top 10 risks, maps attack paths into a graph, and stores replayable attack simulations for regression testing across builds.

## Next Milestones

- Background scan jobs with progress streaming
- PostgreSQL persistence option
- Neo4j attack path persistence
- GitHub Actions workflow for CI scans
- OpenAI/local LLM planner behind the attack generator
- HAR/proxy traffic import for shadow API discovery
- GraphQL introspection importer
- HTML/PDF remediation report export
