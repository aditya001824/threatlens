import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bug,
  Database,
  Download,
  FileText,
  GitBranch,
  History,
  KeyRound,
  Play,
  Radar,
  RefreshCcw,
  ShieldCheck,
  Upload,
  Zap
} from "lucide-react";
import AttackGraph from "./AttackGraph.jsx";
import {
  analyzeJwt,
  generateAttacks,
  getGraph,
  getReport,
  getReportMarkdown,
  health,
  importOpenApi,
  listAttacks,
  listEndpoints,
  listScans,
  replayAttack,
  runScan
} from "./api.js";

const sampleSpec = `openapi: 3.0.3
info:
  title: APIRECON-X Demo Target
  version: 0.1.0
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
paths:
  /login:
    post:
      tags: [auth]
      summary: Login
      security: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                username: { type: string }
                password: { type: string }
      responses:
        "200": { description: Token }
  /users/{user_id}:
    get:
      tags: [users]
      summary: Read user profile
      parameters:
        - name: user_id
          in: path
          required: true
          schema: { type: string }
      responses:
        "200":
          description: User profile
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: { type: string }
                  email: { type: string }
                  role: { type: string }
                  api_token: { type: string }
    patch:
      tags: [users]
      summary: Update user profile
      parameters:
        - name: user_id
          in: path
          required: true
          schema: { type: string }
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                email: { type: string }
                role: { type: string }
                is_admin: { type: boolean }
      responses:
        "200": { description: Updated }
  /admin/users:
    get:
      tags: [admin]
      summary: List users
      responses:
        "200": { description: Users }
  /transfer:
    post:
      tags: [payments]
      summary: Transfer funds
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                sender: { type: string }
                receiver: { type: string }
                amount: { type: integer }
      responses:
        "200": { description: Queued }
  /coupon/apply:
    post:
      tags: [commerce]
      summary: Apply coupon
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                user_id: { type: string }
                code: { type: string }
                discount: { type: integer }
      responses:
        "200": { description: Applied }
  /webhook/test:
    post:
      tags: [integrations]
      summary: Test webhook
      parameters:
        - name: callback_url
          in: query
          schema: { type: string }
      responses:
        "200": { description: Accepted }`;

const tabs = [
  { id: "discovery", label: "Discovery", icon: Radar },
  { id: "scanner", label: "Scanner", icon: Bug },
  { id: "graph", label: "Graph", icon: GitBranch },
  { id: "replay", label: "Replay", icon: Play },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "jwt", label: "JWT", icon: KeyRound }
];

export default function App() {
  const [activeTab, setActiveTab] = useState("discovery");
  const [apiStatus, setApiStatus] = useState("checking");
  const [endpoints, setEndpoints] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [scans, setScans] = useState([]);
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    refreshAll();
  }, []);

  async function refreshAll() {
    try {
      const [healthResult, endpointResult, attackResult, scanResult, graphResult] = await Promise.all([
        health(),
        listEndpoints(),
        listAttacks(),
        listScans(),
        getGraph()
      ]);
      setApiStatus(healthResult.status);
      setEndpoints(endpointResult);
      setAttacks(attackResult);
      setScans(scanResult);
      setGraph(graphResult);
    } catch (error) {
      setApiStatus("offline");
      setMessage(error.message);
    }
  }

  async function action(fn, success) {
    setLoading(true);
    setMessage("");
    try {
      const result = await fn();
      setMessage(success(result));
      await refreshAll();
      return result;
    } catch (error) {
      setMessage(error.message);
      return null;
    } finally {
      setLoading(false);
    }
  }

  const severityCounts = useMemo(() => {
    const latest = scans[0];
    return latest?.severity_counts || {};
  }, [scans]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={24} />
          <div>
            <strong>APIRECON-X</strong>
            <span>{apiStatus}</span>
          </div>
        </div>
        <nav className="nav-tabs">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                className={activeTab === tab.id ? "active" : ""}
                onClick={() => setActiveTab(tab.id)}
                title={tab.label}
              >
                <Icon size={18} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="metric">
            <Database size={18} />
            <span>{endpoints.length}</span>
            <small>Endpoints</small>
          </div>
          <div className="metric">
            <Activity size={18} />
            <span>{attacks.length}</span>
            <small>Attacks</small>
          </div>
          <div className="metric danger">
            <Bug size={18} />
            <span>{severityCounts.high || 0}</span>
            <small>High</small>
          </div>
          <button className="icon-button" onClick={refreshAll} title="Refresh">
            <RefreshCcw size={18} />
          </button>
        </header>

        {message && <div className="status-line">{message}</div>}

        {activeTab === "discovery" && <DiscoveryView loading={loading} action={action} endpoints={endpoints} />}
        {activeTab === "scanner" && <ScannerView loading={loading} action={action} endpoints={endpoints} />}
        {activeTab === "graph" && <GraphView graph={graph} />}
        {activeTab === "replay" && <ReplayView loading={loading} action={action} attacks={attacks} />}
        {activeTab === "reports" && <ReportsView scans={scans} />}
        {activeTab === "jwt" && <JwtView loading={loading} action={action} />}
      </main>
    </div>
  );
}

function DiscoveryView({ loading, action, endpoints }) {
  const [specText, setSpecText] = useState(sampleSpec);
  const [specUrl, setSpecUrl] = useState("");
  const [selectedEndpoint, setSelectedEndpoint] = useState("");
  const [generated, setGenerated] = useState([]);

  return (
    <section className="view-grid two">
      <div className="panel">
        <div className="panel-title">
          <Upload size={18} />
          <h1>OpenAPI Import</h1>
        </div>
        <input
          value={specUrl}
          onChange={(event) => setSpecUrl(event.target.value)}
          placeholder="http://127.0.0.1:9000/openapi.json"
        />
        <textarea value={specText} onChange={(event) => setSpecText(event.target.value)} spellCheck="false" />
        <button
          className="primary"
          disabled={loading}
          onClick={() =>
            action(
              () => importOpenApi(specUrl ? { spec_url: specUrl, source_name: "openapi-url" } : { spec_text: specText, source_name: "textarea" }),
              (result) => `Imported ${result.imported} endpoints`
            )
          }
        >
          <Upload size={16} />
          Import
        </button>
      </div>

      <div className="panel">
        <div className="panel-title">
          <Radar size={18} />
          <h1>Endpoint Inventory</h1>
        </div>
        <EndpointTable endpoints={endpoints} onSelect={setSelectedEndpoint} selectedEndpoint={selectedEndpoint} />
        <button
          className="secondary"
          disabled={!selectedEndpoint || loading}
          onClick={() =>
            action(
              () => generateAttacks(selectedEndpoint),
              (result) => {
                setGenerated(result);
                return `Generated ${result.length} attacks`;
              }
            )
          }
        >
          <Bug size={16} />
          Generate
        </button>
        <div className="attack-list">
          {generated.map((attack) => (
            <div key={attack.id} className="attack-row">
              <span>{attack.category}</span>
              <strong>{attack.name}</strong>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ScannerView({ loading, action, endpoints }) {
  const [targetBaseUrl, setTargetBaseUrl] = useState("http://127.0.0.1:9000");
  const [authHeader, setAuthHeader] = useState("Authorization: Bearer user-1");
  const [secondaryHeader, setSecondaryHeader] = useState("Authorization: Bearer user-2");
  const [authorized, setAuthorized] = useState(true);
  const [dryRun, setDryRun] = useState(false);
  const [maxRequests, setMaxRequests] = useState(8);
  const [rateBurst, setRateBurst] = useState(8);
  const [result, setResult] = useState(null);

  const scanPayload = {
    target_base_url: targetBaseUrl,
    auth_headers: parseHeader(authHeader),
    secondary_auth_headers: parseHeader(secondaryHeader),
    authorized,
    dry_run: dryRun,
    max_requests_per_endpoint: Number(maxRequests),
    rate_limit_burst: Number(rateBurst)
  };

  return (
    <section className="view-grid two">
      <div className="panel">
        <div className="panel-title">
          <Bug size={18} />
          <h1>Scan Launcher</h1>
        </div>
        <label>
          Target
          <input value={targetBaseUrl} onChange={(event) => setTargetBaseUrl(event.target.value)} />
        </label>
        <label>
          Primary Header
          <input value={authHeader} onChange={(event) => setAuthHeader(event.target.value)} />
        </label>
        <label>
          Secondary Header
          <input value={secondaryHeader} onChange={(event) => setSecondaryHeader(event.target.value)} />
        </label>
        <div className="number-grid">
          <label>
            Max Requests
            <input type="number" min="1" max="25" value={maxRequests} onChange={(event) => setMaxRequests(event.target.value)} />
          </label>
          <label>
            Burst
            <input type="number" min="2" max="30" value={rateBurst} onChange={(event) => setRateBurst(event.target.value)} />
          </label>
        </div>
        <div className="switch-row">
          <label>
            <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
            Authorized
          </label>
          <label>
            <input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} />
            Dry Run
          </label>
        </div>
        <button
          className="primary"
          disabled={!endpoints.length || loading}
          onClick={() =>
            action(
              () => runScan(scanPayload),
              (scanResult) => {
                setResult(scanResult);
                return `Scan ${scanResult.summary.status}: ${scanResult.summary.findings_count} findings`;
              }
            )
          }
        >
          <Play size={16} />
          Run
        </button>
        <button
          className="secondary left-gap"
          disabled={loading}
          onClick={() =>
            action(
              async () => {
                await importOpenApi({ spec_url: "http://127.0.0.1:9000/openapi.json", source_name: "demo-target" });
                return runScan({ ...scanPayload, target_base_url: "http://127.0.0.1:9000", authorized: true });
              },
              (scanResult) => {
                setResult(scanResult);
                return `Demo scan complete: ${scanResult.summary.findings_count} findings`;
              }
            )
          }
        >
          <Zap size={16} />
          Demo Run
        </button>
      </div>

      <div className="panel">
        <div className="panel-title">
          <Activity size={18} />
          <h1>Findings</h1>
        </div>
        <Findings findings={result?.findings || []} />
      </div>
    </section>
  );
}

function ReportsView({ scans }) {
  const [selectedScanId, setSelectedScanId] = useState("");
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loadingReport, setLoadingReport] = useState(false);

  useEffect(() => {
    if (!selectedScanId && scans.length) {
      setSelectedScanId(scans[0].scan_id);
    }
  }, [scans, selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) return;
    setLoadingReport(true);
    setError("");
    getReport(selectedScanId)
      .then(setReport)
      .catch((loadError) => setError(loadError.message))
      .finally(() => setLoadingReport(false));
  }, [selectedScanId]);

  async function downloadMarkdown() {
    if (!selectedScanId) return;
    try {
      const markdown = await getReportMarkdown(selectedScanId);
      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `apireconx-report-${selectedScanId}.md`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (downloadError) {
      setError(downloadError.message);
    }
  }

  return (
    <section className="view-grid reports-grid">
      <div className="panel">
        <div className="panel-title">
          <History size={18} />
          <h1>Scan History</h1>
        </div>
        <div className="scan-list">
          {scans.map((scan) => (
            <button
              key={scan.scan_id}
              className={selectedScanId === scan.scan_id ? "scan-item active" : "scan-item"}
              onClick={() => setSelectedScanId(scan.scan_id)}
            >
              <span>{new Date(scan.started_at).toLocaleString()}</span>
              <strong>{scan.findings_count} findings</strong>
              <small>{scan.attacks_executed} attacks</small>
            </button>
          ))}
          {!scans.length && <div className="empty">No scans</div>}
        </div>
      </div>

      <div className="panel">
        <div className="panel-title report-title">
          <FileText size={18} />
          <h1>Risk Report</h1>
          <button className="icon-button" title="Download Markdown" disabled={!report} onClick={downloadMarkdown}>
            <Download size={16} />
          </button>
        </div>
        {error && <div className="status-line">{error}</div>}
        {loadingReport && <div className="empty">Loading report</div>}
        {report && !loadingReport && (
          <div className="report-body">
            <div className="report-hero">
              <div className="risk-score">{report.risk_score}</div>
              <div>
                <strong>{report.scan.target_base_url}</strong>
                <p>{report.executive_summary}</p>
              </div>
            </div>
            <SeverityBars counts={report.severity_counts} />
            <div className="category-grid">
              {Object.entries(report.category_counts).map(([category, count]) => (
                <div key={category} className="category-chip">
                  <span>{category}</span>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
            <h2>Top Findings</h2>
            <Findings findings={report.top_findings} />
            <h2>Recommendations</h2>
            <div className="recommendations">
              {report.recommendations.map((recommendation) => (
                <div key={recommendation}>{recommendation}</div>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function SeverityBars({ counts }) {
  const severities = ["critical", "high", "medium", "low", "info"];
  const max = Math.max(1, ...severities.map((severity) => counts?.[severity] || 0));
  return (
    <div className="severity-bars">
      {severities.map((severity) => {
        const count = counts?.[severity] || 0;
        return (
          <div key={severity} className="severity-row">
            <span>{severity}</span>
            <div>
              <i style={{ width: `${Math.max(6, (count / max) * 100)}%` }} className={`bar-${severity}`} />
            </div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </div>
  );
}

function GraphView({ graph }) {
  return (
    <section className="panel wide">
      <div className="panel-title">
        <GitBranch size={18} />
        <h1>Attack Path Graph</h1>
      </div>
      <AttackGraph graph={graph} />
    </section>
  );
}

function ReplayView({ loading, action, attacks }) {
  const [authorized, setAuthorized] = useState(true);
  return (
    <section className="panel wide">
      <div className="panel-title">
        <Play size={18} />
        <h1>Attack Replay</h1>
      </div>
      <div className="switch-row compact">
        <label>
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
          Authorized
        </label>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Attack</th>
              <th>Method</th>
              <th>Status</th>
              <th>Impact</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {attacks.map((attack) => (
              <tr key={attack.id}>
                <td>{attack.name}</td>
                <td>{attack.method}</td>
                <td>{attack.status_code || "-"}</td>
                <td>{attack.impact}</td>
                <td>
                  <button
                    className="icon-button"
                    disabled={loading}
                    title="Replay"
                    onClick={() =>
                      action(
                        () => replayAttack(attack.id, { authorized }),
                        (result) => `Replay returned ${result.status_code}`
                      )
                    }
                  >
                    <RefreshCcw size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function JwtView({ loading, action }) {
  const [token, setToken] = useState("");
  const [analysis, setAnalysis] = useState(null);

  return (
    <section className="view-grid two">
      <div className="panel">
        <div className="panel-title">
          <KeyRound size={18} />
          <h1>JWT Analyzer</h1>
        </div>
        <textarea value={token} onChange={(event) => setToken(event.target.value)} placeholder="eyJ..." spellCheck="false" />
        <button
          className="primary"
          disabled={!token || loading}
          onClick={() =>
            action(
              () => analyzeJwt({ token }),
              (result) => {
                setAnalysis(result);
                return `JWT risk score ${result.risk_score}`;
              }
            )
          }
        >
          <KeyRound size={16} />
          Analyze
        </button>
      </div>
      <div className="panel">
        <div className="panel-title">
          <ShieldCheck size={18} />
          <h1>Token Findings</h1>
        </div>
        {analysis && (
          <>
            <div className="risk-score">{analysis.risk_score}</div>
            <Findings
              findings={analysis.findings.map((finding, index) => ({
                id: `${finding.title}-${index}`,
                severity: finding.severity,
                title: finding.title,
                description: finding.detail,
                category: "jwt"
              }))}
            />
            <pre>{JSON.stringify({ header: analysis.header, payload: analysis.payload }, null, 2)}</pre>
          </>
        )}
      </div>
    </section>
  );
}

function EndpointTable({ endpoints, selectedEndpoint, onSelect }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th></th>
            <th>Method</th>
            <th>Path</th>
            <th>Auth</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.map((endpoint) => (
            <tr key={endpoint.id} className={selectedEndpoint === endpoint.id ? "selected" : ""}>
              <td>
                <input
                  type="radio"
                  name="endpoint"
                  checked={selectedEndpoint === endpoint.id}
                  onChange={() => onSelect(endpoint.id)}
                />
              </td>
              <td>
                <code>{endpoint.method}</code>
              </td>
              <td>{endpoint.path}</td>
              <td>{endpoint.auth_required ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Findings({ findings }) {
  if (!findings.length) {
    return <div className="empty">No findings</div>;
  }
  return (
    <div className="findings">
      {findings.map((finding) => (
        <article key={finding.id} className={`finding ${finding.severity}`}>
          <div>
            <span>{finding.severity}</span>
            <strong>{finding.title}</strong>
          </div>
          <p>{finding.description}</p>
        </article>
      ))}
    </div>
  );
}

function parseHeader(line) {
  if (!line.trim()) return {};
  const index = line.indexOf(":");
  if (index === -1) return {};
  return { [line.slice(0, index).trim()]: line.slice(index + 1).trim() };
}
