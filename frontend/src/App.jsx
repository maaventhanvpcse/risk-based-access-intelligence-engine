import { useEffect, useState } from "react"
import "./App.css"

const API_URL =
  "https://risk-based-access-intelligence-engine.onrender.com"

function App() {
  const [form, setForm] = useState({
    user_id: "Alice",
    device_trusted: true,
    device_secure: true,
    location_known: true,
    behaviour_anomaly: 10,
    access_frequency: 10,
    resource_sensitivity: 20,
    failed_attempts: 0,
    threat_level: "none",
  })

  const [result, setResult] = useState(null)
  const [mlResult, setMlResult] = useState(null)
  const [threatIntel, setThreatIntel] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState("Ready to evaluate access")

  function updateField(name, value) {
    setForm((prev) => ({
      ...prev,
      [name]: value,
    }))
  }

  async function loadHistory() {
    try {
      const response = await fetch(`${API_URL}/access/history`)

      if (!response.ok) {
        throw new Error(`History API returned ${response.status}`)
      }

      const data = await response.json()

      const historyData = Array.isArray(data.history)
        ? data.history
        : Array.isArray(data)
        ? data
        : []

      setHistory(historyData)
    } catch (error) {
      console.error("History loading failed:", error)
    }
  }

  useEffect(() => {
    loadHistory()

    const interval = setInterval(() => {
      loadHistory()
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  async function evaluateAccess() {
    setLoading(true)
    setStatus("Evaluating access request...")

    try {
      const response = await fetch(`${API_URL}/access/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data?.detail || "Access evaluation failed")
      }

      const evaluation =
        data.access_evaluation ||
        data.data?.access_evaluation ||
        data.data ||
        data

      const ml =
        data.ml_behaviour ||
        data.data?.ml_behaviour ||
        evaluation.ml_behaviour ||
        null

      const threat =
        data.threat_intelligence ||
        data.data?.threat_intelligence ||
        evaluation.threat_intelligence ||
        null

      setResult(evaluation)
      setMlResult(ml)
      setThreatIntel(threat)

      await loadHistory()

      setStatus("Decision generated successfully")
    } catch (error) {
      console.error("Evaluation failed:", error)
      setResult(null)
      setMlResult(null)
      setThreatIntel(null)
      setStatus(`Backend error: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }

  const totalRequests = history.length

  const allowCount = history.filter(
    (item) => String(item.decision).toUpperCase() === "ALLOW"
  ).length

  const challengeCount = history.filter(
    (item) => String(item.decision).toUpperCase() === "CHALLENGE"
  ).length

  const restrictCount = history.filter(
    (item) => String(item.decision).toUpperCase() === "RESTRICT"
  ).length

  const denyCount = history.filter(
    (item) => String(item.decision).toUpperCase() === "DENY"
  ).length

  const averageRisk =
    history.length > 0
      ? Math.round(
          history.reduce(
            (sum, item) => sum + Number(item.risk_score || 0),
            0
          ) / history.length
        )
      : 0

  const latestRecord = history.length > 0 ? history[0] : null

  const latestMLAnomaly =
    latestRecord?.ml_anomaly_score ??
    mlResult?.anomaly_score ??
    0

  const latestThreatScore =
    latestRecord?.threat_score ??
    threatIntel?.threat_score ??
    0

  const latestThreatLevel =
    latestRecord?.intelligence_threat_level ??
    latestRecord?.threat_level ??
    threatIntel?.threat_level ??
    "NONE"

  const latestDecision =
    latestRecord?.decision ??
    result?.decision ??
    "—"

  const decisionClass =
    String(result?.decision || "").toLowerCase()

  const mlStatusClass =
    String(mlResult?.status || "").toLowerCase()

  const threatLevelClass =
    String(threatIntel?.threat_level || "").toLowerCase()

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>🛡️ Risk-Based Access Intelligence Engine</h1>
          <p>
            Context-Aware • Risk-Sensitive • Continuous Access Evaluation
          </p>
        </div>

        <div className="monitor-badge">
          <span className="monitor-dot"></span>
          Monitoring Active
        </div>
      </header>

      <main className="container">
        {/* OVERVIEW */}
        <section className="overview-grid">
          <StatCard
            icon="📊"
            label="Total Requests"
            value={totalRequests}
          />

          <StatCard
            icon="✓"
            label="Allowed"
            value={allowCount}
            cls="allow-icon"
          />

          <StatCard
            icon="!"
            label="Challenged"
            value={challengeCount}
            cls="challenge-icon"
          />

          <StatCard
            icon="◐"
            label="Restricted"
            value={restrictCount}
            cls="restrict-icon"
          />

          <StatCard
            icon="×"
            label="Denied"
            value={denyCount}
            cls="deny-icon"
          />

          <StatCard
            icon="⚖"
            label="Average Risk"
            value={averageRisk}
          />
        </section>

        {/* LIVE MONITORING */}
        <section className="monitor-card">
          <div className="monitor-header">
            <div>
              <h2>🔎 Live Risk Monitoring</h2>
              <p>
                Continuous access activity and intelligence monitoring
              </p>
            </div>

            <div className="refresh-label">
              Auto refresh: 5s
            </div>
          </div>

          <div className="monitor-grid">
            <MonitorItem
              label="Latest ML Anomaly"
              value={latestMLAnomaly}
            />

            <MonitorItem
              label="Latest Threat"
              value={String(latestThreatLevel).toUpperCase()}
              cls={String(latestThreatLevel).toLowerCase()}
            />

            <MonitorItem
              label="Latest Decision"
              value={String(latestDecision).toUpperCase()}
              cls={String(latestDecision).toLowerCase()}
            />

            <MonitorItem
              label="Latest Risk"
              value={latestRecord?.risk_score ?? "—"}
            />
          </div>
        </section>

        <div className="grid">
          {/* LEFT SIDE - INPUT */}
          <section className="card">
            <div className="section-title">
              <div>
                <h2>Access Request Context</h2>
                <p>
                  Configure the security context for the request
                </p>
              </div>
            </div>

            <div className="field">
              <label>User Identity</label>

              <input
                type="text"
                value={form.user_id}
                onChange={(e) =>
                  updateField("user_id", e.target.value)
                }
                placeholder="Enter user identity"
              />
            </div>

            <SelectField
              label="Device Trust"
              value={form.device_trusted}
              onChange={(value) =>
                updateField("device_trusted", value === "true")
              }
              options={[
                ["true", "Trusted Device"],
                ["false", "Unknown Device"],
              ]}
            />

            <SelectField
              label="Device Security"
              value={form.device_secure}
              onChange={(value) =>
                updateField("device_secure", value === "true")
              }
              options={[
                ["true", "Secure"],
                ["false", "Insecure"],
              ]}
            />

            <SelectField
              label="Location"
              value={form.location_known}
              onChange={(value) =>
                updateField("location_known", value === "true")
              }
              options={[
                ["true", "Known Location"],
                ["false", "Unusual Location"],
              ]}
            />

            <RangeField
              label="Behaviour Anomaly"
              value={form.behaviour_anomaly}
              onChange={(value) =>
                updateField("behaviour_anomaly", value)
              }
            />

            <RangeField
              label="Access Frequency"
              value={form.access_frequency}
              onChange={(value) =>
                updateField("access_frequency", value)
              }
            />

            <RangeField
              label="Resource Sensitivity"
              value={form.resource_sensitivity}
              onChange={(value) =>
                updateField("resource_sensitivity", value)
              }
            />

            <div className="field">
              <label>Failed Access Attempts</label>

              <input
                type="number"
                min="0"
                max="20"
                value={form.failed_attempts}
                onChange={(e) =>
                  updateField(
                    "failed_attempts",
                    Number(e.target.value)
                  )
                }
              />
            </div>

            <SelectField
              label="Threat Signal"
              value={form.threat_level}
              onChange={(value) =>
                updateField("threat_level", value)
              }
              options={[
                ["none", "None"],
                ["low", "Low"],
                ["medium", "Medium"],
                ["high", "High"],
                ["critical", "Critical"],
              ]}
            />

            <button
              className="button"
              onClick={evaluateAccess}
              disabled={loading}
            >
              {loading
                ? "Evaluating Risk..."
                : "Evaluate Access"}
            </button>
          </section>

          {/* RIGHT SIDE - RESULT */}
          <section className="card">
            <div className="section-title">
              <div>
                <h2>Access Intelligence</h2>
                <p>
                  AI-assisted contextual access decision
                </p>
              </div>
            </div>

            {!result ? (
              <div className="empty-result">
                <div className="shield-icon">🛡️</div>

                <h3>Waiting for Access Request</h3>

                <p>
                  Configure the request context and click
                  Evaluate Access.
                </p>
              </div>
            ) : (
              <div className="result">
                <div className="risk-label">
                  Calculated Risk Score
                </div>

                <div className="score">
                  {result.risk_score ?? 0}
                </div>

                <div
                  className={`decision ${decisionClass}`}
                >
                  {String(
                    result.decision || "UNKNOWN"
                  ).toUpperCase()}
                </div>

                <p className="action-text">
                  {result.action ||
                    getDecisionAction(result.decision)}
                </p>

                {/* ML */}
                {mlResult && (
                  <div className="ml-card">
                    <h3>🤖 ML Behaviour Analysis</h3>

                    <div className="ml-grid">
                      <div className="ml-box">
                        <span>ML Anomaly Score</span>

                        <strong>
                          {mlResult.anomaly_score ?? 0}
                        </strong>
                      </div>

                      <div className="ml-box">
                        <span>Behaviour Status</span>

                        <strong
                          className={mlStatusClass}
                        >
                          {String(
                            mlResult.status || "UNKNOWN"
                          ).toUpperCase()}
                        </strong>
                      </div>
                    </div>

                    <div className="ml-meta">
                      <div>
                        Model:{" "}
                        {mlResult.model_status ||
                          "Unknown"}
                      </div>

                      <div>
                        Prediction:{" "}
                        {Number(mlResult.prediction) === 1
                          ? "Anomalous"
                          : "Normal"}
                      </div>
                    </div>
                  </div>
                )}

                {/* THREAT */}
                {threatIntel && (
                  <div
                    className="ml-card"
                    style={{ marginTop: "16px" }}
                  >
                    <h3>🚨 Threat Intelligence</h3>

                    <div className="ml-grid">
                      <div className="ml-box">
                        <span>Threat Score</span>

                        <strong>
                          {threatIntel.threat_score ?? 0}
                        </strong>
                      </div>

                      <div className="ml-box">
                        <span>Threat Level</span>

                        <strong
                          className={threatLevelClass}
                        >
                          {String(
                            threatIntel.threat_level ||
                              "UNKNOWN"
                          ).toUpperCase()}
                        </strong>
                      </div>
                    </div>

                    <div className="ml-meta">
                      <div>
                        Status:{" "}
                        {threatIntel.status || "Unknown"}
                      </div>

                      <div>
                        Indicators:{" "}
                        {threatIntel.indicator_count ?? 0}
                      </div>

                      <div>
                        Source:{" "}
                        {threatIntel.source ||
                          "Threat Intelligence"}
                      </div>
                    </div>

                    {Array.isArray(
                      threatIntel.indicators
                    ) &&
                      threatIntel.indicators.length > 0 && (
                        <div style={{ marginTop: "12px" }}>
                          {threatIntel.indicators.map(
                            (indicator, index) => (
                              <div
                                className="reason"
                                key={index}
                              >
                                • {indicator}
                              </div>
                            )
                          )}
                        </div>
                      )}
                  </div>
                )}

                {/* RISK REASONS */}
                <div className="risk-factors">
                  <h3>Risk Factors</h3>

                  {Array.isArray(result.reasons) &&
                  result.reasons.length > 0 ? (
                    result.reasons.map(
                      (reason, index) => (
                        <div
                          className="reason"
                          key={index}
                        >
                          • {reason}
                        </div>
                      )
                    )
                  ) : (
                    <div className="reason">
                      • No additional risk factors returned.
                    </div>
                  )}
                </div>

                {/* DATABASE */}
                {result.database && (
                  <div className="ml-meta">
                    <div>
                      Persistent Storage:{" "}
                      {result.database.persistent_storage
                        ? "Connected"
                        : "Not Connected"}
                    </div>

                    <div>
                      Saved:{" "}
                      {result.database.saved
                        ? "Yes"
                        : "No"}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="status">
              {status}
            </div>
          </section>
        </div>

        {/* HISTORY */}
        <section className="card history-section">
          <div className="section-title history-title">
            <div>
              <h2>📊 Access History</h2>
              <p>
                Recent access activity monitored by the engine
              </p>
            </div>

            <span className="live-tag">
              ● LIVE
            </span>
          </div>

          {history.length === 0 ? (
            <p className="empty-history">
              No access history available yet.
            </p>
          ) : (
            <div className="history-table-wrapper">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Time</th>
                    <th>Risk</th>
                    <th>Decision</th>
                    <th>Threat</th>
                    <th>Threat Score</th>
                    <th>Behaviour</th>
                    <th>ML Anomaly</th>
                    <th>Failed Attempts</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((item, index) => {
                    const decision = String(
                      item.decision || ""
                    ).toUpperCase()

                    return (
                      <tr
                        key={item.id ?? index}
                      >
                        <td>{item.user_id || "-"}</td>

                        <td>
                          {item.timestamp ||
                            item.created_at ||
                            "-"}
                        </td>

                        <td>
                          <strong>
                            {item.risk_score ?? "-"}
                          </strong>
                        </td>

                        <td>
                          <span
                            className={`table-decision ${decision.toLowerCase()}`}
                          >
                            {decision || "-"}
                          </span>
                        </td>

                        <td>
                          {String(
                            item.intelligence_threat_level ||
                              item.threat_level ||
                              "-"
                          ).toUpperCase()}
                        </td>

                        <td>
                          {item.threat_score ?? "-"}
                        </td>

                        <td>
                          {item.behaviour_anomaly ?? "-"}
                        </td>

                        <td>
                          {item.ml_anomaly_score ?? "-"}
                        </td>

                        <td>
                          {item.failed_attempts ?? "-"}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* PIPELINE */}
        <section className="card pipeline-section">
          <div className="section-title">
            <div>
              <h2>⚙️ How the Engine Works</h2>
              <p>
                Context → ML → Threat Intelligence →
                Risk → Decision
              </p>
            </div>
          </div>

          <div className="pipeline">
            <PipelineStep
              icon="👤"
              label="Identity"
            />

            <Arrow />

            <PipelineStep
              icon="💻"
              label="Device"
            />

            <Arrow />

            <PipelineStep
              icon="📍"
              label="Location"
            />

            <Arrow />

            <PipelineStep
              icon="🤖"
              label="ML Behaviour"
            />

            <Arrow />

            <PipelineStep
              icon="🚨"
              label="Threat Intel"
            />

            <Arrow />

            <PipelineStep
              icon="📊"
              label="Risk Engine"
            />

            <Arrow />

            <PipelineStep
              icon="⚖️"
              label="Decision"
            />
          </div>
        </section>
      </main>

      <footer className="footer">
        Risk-Based Access Intelligence Engine
        <br />
        React + FastAPI + Python ML + Threat Intelligence
      </footer>
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  cls = "",
}) {
  return (
    <div className="stat-card">
      <span className={`stat-icon ${cls}`}>
        {icon}
      </span>

      <div>
        <span className="stat-label">
          {label}
        </span>

        <strong>{value}</strong>
      </div>
    </div>
  )
}

function MonitorItem({
  label,
  value,
  cls = "",
}) {
  return (
    <div className="monitor-item">
      <span>{label}</span>
      <strong className={cls}>
        {value}
      </strong>
    </div>
  )
}

function SelectField({
  label,
  value,
  onChange,
  options,
}) {
  return (
    <div className="field">
      <label>{label}</label>

      <select
        value={String(value)}
        onChange={(e) =>
          onChange(e.target.value)
        }
      >
        {options.map(
          ([optionValue, text]) => (
            <option
              key={optionValue}
              value={optionValue}
            >
              {text}
            </option>
          )
        )}
      </select>
    </div>
  )
}

function RangeField({
  label,
  value,
  onChange,
}) {
  return (
    <div className="field">
      <label>
        {label}
        <span className="range-value">
          {value}
        </span>
      </label>

      <input
        type="range"
        min="0"
        max="100"
        value={value}
        onChange={(e) =>
          onChange(Number(e.target.value))
        }
      />
    </div>
  )
}

function PipelineStep({
  icon,
  label,
}) {
  return (
    <div className="pipeline-step">
      <div className="pipeline-icon">
        {icon}
      </div>

      <span>{label}</span>
    </div>
  )
}

function Arrow() {
  return (
    <div className="pipeline-arrow">
      →
    </div>
  )
}

function getDecisionAction(decision) {
  const normalized = String(
    decision || ""
  ).toUpperCase()

  switch (normalized) {
    case "ALLOW":
      return "Access permitted."

    case "CHALLENGE":
      return "Additional verification required."

    case "RESTRICT":
      return "Limited access permitted."

    case "DENY":
      return "Access blocked."

    default:
      return "Access decision generated."
  }
}

export default App