
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts'
import './App.css'

const API_URL = 'http://127.0.0.1:8000'

type AlertStatus = 'new' | 'investigating' | 'resolved'
type AlertFilter = 'all' | AlertStatus
type EventFilter = 'all' | 'failed' | 'success'
type SimulationType = 'brute-force' | 'password-spraying'

type SecurityAlert = {
  id: number
  type: string
  severity: string
  ip_address: string
  failed_attempts: number
  timestamp: string
  description: string
  status: AlertStatus
  notes: string
}

type LoginEvent = {
  id: number
  timestamp: string
  ip_address: string
  username: string
  status: 'success' | 'failed'
}

type AlertCounts = {
  new: number
  investigating: number
  resolved: number
  total: number
}


type IpRiskAssessment = {
  ip_address: string
  failed_logins: number
  successful_logins: number
  unique_usernames: number
  alert_count: number
  risk_score: number
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical'
  reasons: string[]
}

type AnalysisResult = {
  events_analyzed: number
  total_alerts: number
  saved_to_database: boolean
}

type Investigation = {
  source_ip: string
  attack_type: string
  severity: string
  detection_time: string
  window_minutes: number
  related_event_count: number
  affected_accounts: string[]
  affected_account_count: number
  related_events: LoginEvent[]
  correlation_method: 'exact' | 'historical'
}

type InvestigationResponse = {
  alert: SecurityAlert
  investigation: Investigation
}

const statusLabels: Record<AlertStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved'
}

function App() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [events, setEvents] = useState<LoginEvent[]>([])

  const [ipRisks, setIpRisks] = useState<
    Record<string, IpRiskAssessment>
  >({})


  const [alertCounts, setAlertCounts] = useState<AlertCounts>({
    new: 0,
    investigating: 0,
    resolved: 0,
    total: 0
  })

  const [alertFilter, setAlertFilter] = useState<AlertFilter>('all')
  const [eventFilter, setEventFilter] = useState<EventFilter>('all')
  const [ipSearch, setIpSearch] = useState('')

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [simulationLoading, setSimulationLoading] =
    useState<SimulationType | null>(null)
  const [simulationMessage, setSimulationMessage] = useState('')
  const [simulationError, setSimulationError] = useState('')

  const [selectedInvestigation, setSelectedInvestigation] =
    useState<InvestigationResponse | null>(null)
  const [investigationLoading, setInvestigationLoading] =
    useState<number | null>(null)
  const [investigationError, setInvestigationError] = useState('')

  const [noteDraft, setNoteDraft] = useState('')
  const [noteSaving, setNoteSaving] = useState(false)
  const [noteMessage, setNoteMessage] = useState('')
  const [noteError, setNoteError] = useState('')
  const noteSavingRef = useRef(false)


  const [updatingAlertId, setUpdatingAlertId] =
    useState<number | null>(null)
  const [statusMessage, setStatusMessage] = useState('')
  const [statusError, setStatusError] = useState('')

  const mounted = useRef(true)
  const simulationBusy = useRef(false)
  const investigationRequest = useRef(0)
  const statusUpdateBusy = useRef(false)

  // ========================================
  // FETCH DASHBOARD DATA
  // ========================================

  const fetchSecurityData = useCallback(async () => {
    try {
      const [alertsResponse, eventsResponse, countsResponse] =
        await Promise.all([
          fetch(`${API_URL}/alerts`),
          fetch(`${API_URL}/events`),
          fetch(`${API_URL}/alerts/status/counts`)
        ])

      if (
        !alertsResponse.ok ||
        !eventsResponse.ok ||
        !countsResponse.ok
      ) {
        throw new Error('Unable to retrieve security data')
      }

      const alertsData = await alertsResponse.json()
      const eventsData = await eventsResponse.json()
      const countsData: AlertCounts = await countsResponse.json()

      // Retrieve risk assessments for each unique alert IP.
      const uniqueIps: string[] = [
        ...new Set(
          (alertsData.alerts as SecurityAlert[]).map(
            (alert) => alert.ip_address
          )
        )
      ]

      const riskResults = await Promise.allSettled(
        uniqueIps.map(async (ip): Promise<IpRiskAssessment> => {
          const response = await fetch(
            `${API_URL}/risk/ip/${encodeURIComponent(ip)}`
          )

          if (!response.ok) {
            throw new Error(`Unable to assess risk for ${ip}`)
          }

          return (await response.json()) as IpRiskAssessment
        })
      )

      const updatedRisks: Record<string, IpRiskAssessment> = {}

      riskResults.forEach((result) => {
        if (result.status === 'fulfilled') {
          updatedRisks[result.value.ip_address] = result.value
        }
      })

      if (mounted.current && !statusUpdateBusy.current) {
        setAlerts(alertsData.alerts)
        setEvents(eventsData.events)
        setAlertCounts(countsData)
        setIpRisks(updatedRisks)
        setError('')
      }

    } catch {
      if (mounted.current) {
        setError('Cannot connect to Sentinel backend')
      }
    } finally {
      if (mounted.current) {
        setLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    void fetchSecurityData()

    const interval = setInterval(() => {
      void fetchSecurityData()
    }, 5000)

    return () => {
      mounted.current = false
      clearInterval(interval)
      investigationRequest.current += 1
    }
  }, [fetchSecurityData])

  // ========================================
  // THREAT SIMULATIONS
  // ========================================

  async function runSimulation(type: SimulationType) {
    if (simulationBusy.current) return

    simulationBusy.current = true
    setSimulationLoading(type)
    setSimulationMessage('')
    setSimulationError('')

    const usernames =
      type === 'brute-force'
        ? Array(5).fill('admin')
        : ['alice', 'bob', 'charlie', 'david', 'emma']

    const randomByte = Math.floor(Math.random() * 254) + 1

    const ipAddress =
      type === 'brute-force'
        ? `192.0.2.${randomByte}`
        : `198.51.100.${randomByte}`

    const baseTime = Date.now()

    const generatedEvents = usernames.map((username, index) => ({
      timestamp: new Date(baseTime + index * 1000).toISOString(),
      ip_address: ipAddress,
      username,
      status: 'failed' as const
    }))

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ events: generatedEvents })
      })

      if (!response.ok) {
        throw new Error('Simulation request failed')
      }

      const result: AnalysisResult = await response.json()

      if (!result.saved_to_database) {
        throw new Error('Events were not saved')
      }

      await fetchSecurityData()

      if (mounted.current) {
        const name =
          type === 'brute-force'
            ? 'Brute-force'
            : 'Password-spraying'

        setSimulationMessage(
          `${name} simulation complete: ` +
          `${result.events_analyzed} events analyzed, ` +
          `${result.total_alerts} alert(s) detected. ` +
          `Source IP: ${ipAddress}`
        )
      }
    } catch {
      if (mounted.current) {
        setSimulationError(
          'Unable to complete the simulation. ' +
          'Check that the Sentinel backend is running.'
        )
      }
    } finally {
      simulationBusy.current = false

      if (mounted.current) {
        setSimulationLoading(null)
      }
    }
  }

  // ========================================
  // UPDATE ALERT STATUS
  // ========================================

  async function changeAlertStatus(
    alertId: number,
    newStatus: AlertStatus
  ) {
    if (statusUpdateBusy.current) return

    statusUpdateBusy.current = true
    setUpdatingAlertId(alertId)
    setStatusMessage('')
    setStatusError('')

    try {
      const response = await fetch(
        `${API_URL}/alerts/${alertId}/status`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            status: newStatus
          })
        }
      )

      if (!response.ok) {
        throw new Error('Unable to update alert status')
      }

      const result: { alert: SecurityAlert } =
        await response.json()

      if (mounted.current) {
        setAlerts((previous) =>
          previous.map((alert) =>
            alert.id === alertId
              ? result.alert
              : alert
          )
        )

        setSelectedInvestigation((previous) => {
          if (!previous || previous.alert.id !== alertId) {
            return previous
          }

          return {
            ...previous,
            alert: result.alert
          }
        })

        setStatusMessage(
          `Alert #${alertId} changed to ` +
          `${statusLabels[newStatus]}.`
        )
      }
    } catch {
      if (mounted.current) {
        setStatusError(
          `Unable to update Alert #${alertId}. ` +
          'Please try again.'
        )
      }
    } finally {
      statusUpdateBusy.current = false

      if (mounted.current) {
        setUpdatingAlertId(null)
      }

      await fetchSecurityData()
    }
  }

  // ========================================
  // INVESTIGATE ALERT
  // ========================================

  async function investigateAlert(alertId: number) {
    const requestId = ++investigationRequest.current

    setSelectedInvestigation(null)
    setInvestigationError('')
    setInvestigationLoading(alertId)

    try {
      const response = await fetch(
        `${API_URL}/alerts/${alertId}/investigate`
      )

      if (!response.ok) {
        throw new Error('Investigation request failed')
      }

      const data: InvestigationResponse = await response.json()

      if (
        mounted.current &&
        requestId === investigationRequest.current
      ) {
        
        setSelectedInvestigation(data)
        setNoteDraft(data.alert.notes ?? '')
        setNoteMessage('')
        setNoteError('')

      }
    } catch {
      if (
        mounted.current &&
        requestId === investigationRequest.current
      ) {
        setInvestigationError(
          'Unable to load investigation details.'
        )
      }
    } finally {
      if (
        mounted.current &&
        requestId === investigationRequest.current
      ) {
        setInvestigationLoading(null)
      }
    }
  }


  // ========================================
  // SAVE INVESTIGATION NOTES
  // ========================================

  async function saveInvestigationNotes() {
    if (!selectedInvestigation || noteSavingRef.current) {
      return
    }

    const alertId = selectedInvestigation.alert.id
    const notes = noteDraft

    noteSavingRef.current = true
    setNoteSaving(true)
    setNoteMessage('')
    setNoteError('')

    try {
      const response = await fetch(
        `${API_URL}/alerts/${alertId}/notes`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ notes })
        }
      )

      if (!response.ok) {
        throw new Error('Unable to save notes')
      }

      const result: { alert: SecurityAlert } =
        await response.json()

      if (mounted.current) {
        setAlerts((previous) =>
          previous.map((alert) =>
            alert.id === alertId
              ? result.alert
              : alert
          )
        )

        setSelectedInvestigation((previous) => {
          if (!previous || previous.alert.id !== alertId) {
            return previous
          }

          return {
            ...previous,
            alert: result.alert
          }
        })

        setNoteMessage('Investigation notes saved successfully.')
      }
    } catch {
      if (mounted.current) {
        setNoteError(
          'Unable to save investigation notes. Please try again.'
        )
      }
    } finally {
      noteSavingRef.current = false

      if (mounted.current) {
        setNoteSaving(false)
      }
    }
  }


  function closeInvestigation() {
    investigationRequest.current += 1
    setSelectedInvestigation(null)
    setInvestigationLoading(null)
    setInvestigationError('')
  }

  // ========================================
  // DASHBOARD STATISTICS
  // ========================================

  const failedLogins = events.filter(
    (event) => event.status === 'failed'
  ).length

  const successfulLogins = events.filter(
    (event) => event.status === 'success'
  ).length

  const chartData = [
    { name: 'Successful', count: successfulLogins },
    { name: 'Failed', count: failedLogins }
  ]

  const filteredAlerts = alerts.filter(
    (alert) =>
      alertFilter === 'all' ||
      alert.status === alertFilter
  )

  const filteredEvents = events.filter((event) => {
    const matchesStatus =
      eventFilter === 'all' ||
      event.status === eventFilter

    const matchesIP = event.ip_address
      .toLowerCase()
      .includes(ipSearch.trim().toLowerCase())

    return matchesStatus && matchesIP
  })

  // ========================================
  // RENDER DASHBOARD
  // ========================================

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <h2>◈ SENTINEL</h2>
        <p>SECURITY OPERATIONS</p>

        <nav>
          <a className="active" href="#overview">
            Overview
          </a>
          <a href="#simulations">
            Threat Simulation
          </a>
          <a href="#alerts">
            Threat Alerts
          </a>
          <a href="#activity">
            Login Activity
          </a>
        </nav>
      </aside>

      <main className="main-content" id="overview">
        <header>
          <div>
            <h1>Security Overview</h1>
            <p>
              Monitoring security events and suspicious activity.
            </p>
          </div>

          <span
            className={
              error
                ? 'system-status status-error'
                : 'system-status'
            }
          >
            {error
              ? '● Connection Error'
              : loading
                ? '● Connecting...'
                : '● System Online'}
          </span>
        </header>

        {error && (
          <p className="error-message">{error}</p>
        )}

        {/* ==================================
            MAIN STATISTICS
        ================================== */}

        <section className="stats">
          <div className="stat-card">
            <p>Total Events</p>
            <h2>{loading ? '...' : events.length}</h2>
            <span>Login events recorded</span>
          </div>

          <div className="stat-card">
            <p>Security Alerts</p>
            <h2>{loading ? '...' : alertCounts.total}</h2>
            <span>Potential threats detected</span>
          </div>

          <div className="stat-card">
            <p>Failed Logins</p>
            <h2>{loading ? '...' : failedLogins}</h2>
            <span>Unsuccessful login attempts</span>
          </div>
        </section>

        {/* ==================================
            ALERT MANAGEMENT SUMMARY
        ================================== */}

        <section className="panel" id="alert-management">
          <h2>Alert Management Overview</h2>
          <p>
            Track security alerts from initial detection
            through investigation and resolution.
          </p>

          <div className="alert-status-summary">
            <div className="alert-status-card status-new-card">
              <span>New Alerts</span>
              <strong>
                {loading ? '...' : alertCounts.new}
              </strong>
              <small>Awaiting investigation</small>
            </div>

            <div className="alert-status-card status-investigating-card">
              <span>Investigating</span>
              <strong>
                {loading ? '...' : alertCounts.investigating}
              </strong>
              <small>Currently under review</small>
            </div>

            <div className="alert-status-card status-resolved-card">
              <span>Resolved</span>
              <strong>
                {loading ? '...' : alertCounts.resolved}
              </strong>
              <small>Investigation completed</small>
            </div>
          </div>
        </section>

        {/* ==================================
            LOGIN ANALYTICS
        ================================== */}

        <section className="panel">
          <h2>Login Activity Analytics</h2>
          <p>Successful versus failed login attempts</p>

          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#24334a"
                />

                <XAxis
                  dataKey="name"
                  stroke="#8495b0"
                />

                <YAxis
                  stroke="#8495b0"
                  allowDecimals={false}
                />

                <Tooltip
                  contentStyle={{
                    backgroundColor: '#101c2d',
                    border: '1px solid #24334a',
                    borderRadius: '8px',
                    color: '#ffffff'
                  }}
                />

                <Bar
                  dataKey="count"
                  fill="#48c6ef"
                  radius={[6, 6, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        {/* ==================================
            THREAT SIMULATION LAB
        ================================== */}

        <section className="panel" id="simulations">
          <div className="simulation-heading">
            <div>
              <h2>Threat Simulation Lab</h2>
              <p>
                Generate synthetic login events to test
                Sentinel's detection engine.
              </p>
            </div>

            <span className="simulation-badge">
              DEMO MODE
            </span>
          </div>

          <div className="simulation-grid">
            <div className="simulation-card">
              <span className="simulation-icon">⚠</span>

              <h3>Brute Force</h3>

              <p>
                Simulate five failed login attempts against
                the same account from one IP.
              </p>

              <button
                className="simulation-button"
                disabled={simulationLoading !== null}
                onClick={() => runSimulation('brute-force')}
              >
                {simulationLoading === 'brute-force'
                  ? 'Running Simulation...'
                  : 'Simulate Brute Force'}
              </button>
            </div>

            <div className="simulation-card">
              <span className="simulation-icon">◎</span>

              <h3>Password Spraying</h3>

              <p>
                Simulate failed login attempts against five
                different accounts from one IP.
              </p>

              <button
                className="simulation-button"
                disabled={simulationLoading !== null}
                onClick={() => runSimulation('password-spraying')}
              >
                {simulationLoading === 'password-spraying'
                  ? 'Running Simulation...'
                  : 'Simulate Password Spraying'}
              </button>
            </div>
          </div>

          {simulationMessage && (
            <p
              className="simulation-feedback simulation-success"
              role="status"
            >
              ✓ {simulationMessage}
            </p>
          )}

          {simulationError && (
            <p
              className="simulation-feedback simulation-failure"
              role="alert"
            >
              {simulationError}
            </p>
          )}

          <p className="simulation-disclaimer">
            These are simulated events generated for testing.
            Sentinel is not monitoring live network traffic.
            Running a simulation saves new events and alerts
            to the local database.
          </p>
        </section>

        {/* ==================================
            SECURITY ALERTS
        ================================== */}

        <section className="panel" id="alerts">
          <h2>Security Alerts</h2>
          <p>
            Investigate detected threats and manage
            their resolution status.
          </p>


          <div className="export-actions">
            <a
              className="export-button"
              href={`${API_URL}/export/alerts`}
              download="sentinel_alerts.csv"
            >
              ↓ Export Alerts CSV
            </a>
          </div>


          {/* ALERT STATUS FILTERS */}

          <div className="alert-filter-buttons">
            {(
              [
                'all',
                'new',
                'investigating',
                'resolved'
              ] as AlertFilter[]
            ).map((filter) => (
              <button
                key={filter}
                className={
                  alertFilter === filter ? 'selected' : ''
                }
                onClick={() => setAlertFilter(filter)}
              >
                {filter === 'all'
                  ? 'All Alerts'
                  : statusLabels[filter]}
              </button>
            ))}
          </div>

          <p className="alert-filter-count">
            Showing {Math.min(filteredAlerts.length, 10)} of{' '}
            {filteredAlerts.length} matching alerts
          </p>

          {statusMessage && (
            <p
              className="simulation-feedback simulation-success"
              role="status"
            >
              ✓ {statusMessage}
            </p>
          )}

          {statusError && (
            <p
              className="simulation-feedback simulation-failure"
              role="alert"
            >
              {statusError}
            </p>
          )}

          {filteredAlerts.length === 0 ? (
            <p>No security alerts match this filter.</p>
          ) : (
            filteredAlerts.slice(0, 10).map((alert) => (
              <div
                className="data-row managed-alert-row"
                key={alert.id}
              >
                <div className="managed-alert-info">
                  <strong>{alert.type}</strong>

                  <p className="alert-id">
                    Alert #{alert.id}
                  </p>

                  <p>
                    {alert.ip_address} — {alert.description}
                  </p>

                  {ipRisks[alert.ip_address] && (
                    <div className="ip-risk-container">
                      <div className="ip-risk-header">
                        <span className="ip-risk-label">
                          IP Risk Assessment
                        </span>

                        <span
                          className={`ip-risk-badge risk-${ipRisks[
                            alert.ip_address
                          ].risk_level.toLowerCase()}`}
                        >
                          {ipRisks[alert.ip_address].risk_level} Risk
                        </span>
                      </div>

                      <div className="ip-risk-score">
                        <strong>
                          {ipRisks[alert.ip_address].risk_score}
                        </strong>
                        <span>/100</span>
                      </div>

                      <div className="ip-risk-track">
                        <div
                          className={`ip-risk-fill risk-${ipRisks[
                            alert.ip_address
                          ].risk_level.toLowerCase()}`}
                          style={{
                            width: `${
                              ipRisks[alert.ip_address].risk_score
                            }%`
                          }}
                        />
                      </div>
                    </div>
                  )}


                      {ipRisks[alert.ip_address].reasons.length > 0 && (
                        <div className="ip-risk-reasons">
                          <p className="ip-risk-reasons-title">
                            Risk Factors
                          </p>

                          <ul>
                            {ipRisks[alert.ip_address].reasons.map(
                              (reason, index) => (
                                <li key={`${reason}-${index}`}>
                                  {reason}
                                </li>
                              )
                            )}
                          </ul>
                        </div>
                      )}



                  <div className="alert-badge-row">
                    <span
                      className={
                        `alert-status-badge alert-status-${alert.status}`
                      }
                    >
                      {statusLabels[alert.status]}
                    </span>

                    <span className="severity-badge">
                      {alert.severity}
                    </span>
                  </div>
                </div>

                <div className="managed-alert-actions">
                  <label htmlFor={`alert-status-${alert.id}`}>
                    Investigation Status
                  </label>

                  <select
                    id={`alert-status-${alert.id}`}
                    className="alert-status-select"
                    value={alert.status}
                    disabled={updatingAlertId !== null}
                    onChange={(event) =>
                      void changeAlertStatus(
                        alert.id,
                        event.target.value as AlertStatus
                      )
                    }
                  >
                    <option value="new">New</option>
                    <option value="investigating">
                      Investigating
                    </option>
                    <option value="resolved">
                      Resolved
                    </option>
                  </select>

                  <button
                    className="investigate-button"
                    disabled={investigationLoading !== null || noteSaving}
                    onClick={() => investigateAlert(alert.id)}
                  >
                    {investigationLoading === alert.id
                      ? 'Loading...'
                      : 'Investigate'}
                  </button>

                  {updatingAlertId === alert.id && (
                    <span className="status-saving">
                      Saving...
                    </span>
                  )}
                </div>
              </div>
            ))
          )}

          {investigationError && (
            <p className="error-message" role="alert">
              {investigationError}
            </p>
          )}

          {/* ==================================
              INVESTIGATION PANEL
          ================================== */}

          {selectedInvestigation && (
            <div className="investigation-panel">
              <div className="investigation-header">
                <div>
                  <span className="investigation-label">
                    SECURITY INVESTIGATION
                  </span>

                  <h3>
                    {selectedInvestigation.investigation.attack_type}
                  </h3>

                  <p className="investigation-alert-id">
                    Alert #{selectedInvestigation.alert.id}
                  </p>

                  <div className="investigation-status">
                    <span
                      className={
                        `alert-status-badge alert-status-${selectedInvestigation.alert.status}`
                      }
                    >
                      {statusLabels[selectedInvestigation.alert.status]}
                    </span>
                  </div>
                </div>

                <button
                  className="close-investigation"
                  onClick={closeInvestigation}
                  disabled={noteSaving}
                >
                  Close Investigation
                </button>
              </div>

              {/* CORRELATION METHOD */}

              <div className="correlation-section">
                {selectedInvestigation.investigation
                  .correlation_method === 'exact' ? (
                  <span className="correlation-badge correlation-exact">
                    ✓ Exact Event Correlation
                  </span>
                ) : (
                  <span className="correlation-badge correlation-historical">
                    ◷ Historical Correlation
                  </span>
                )}
              </div>

              {/* INVESTIGATION DETAILS */}

              <div className="investigation-details">
                <div className="investigation-detail">
                  <span>Source IP</span>
                  <strong>
                    {selectedInvestigation.investigation.source_ip}
                  </strong>
                </div>

                <div className="investigation-detail">
                  <span>Severity</span>
                  <strong>
                    {selectedInvestigation.investigation.severity}
                  </strong>
                </div>

                <div className="investigation-detail">
                  <span>Related Failed Logins</span>
                  <strong>
                    {selectedInvestigation.investigation.related_event_count}
                  </strong>
                </div>

                <div className="investigation-detail">
                  <span>Accounts Affected</span>
                  <strong>
                    {selectedInvestigation.investigation.affected_account_count}
                  </strong>
                </div>
              </div>

              <p className="investigation-timestamp">
                Detected:{' '}
                {new Date(
                  selectedInvestigation.investigation.detection_time
                ).toLocaleString()}
                {' '}· Detection window:{' '}
                {selectedInvestigation.investigation.window_minutes}
                {' '}minutes
              </p>

              {/* AFFECTED ACCOUNTS */}

              <h4>Affected Accounts</h4>

              <div className="account-list">
                {selectedInvestigation.investigation
                  .affected_accounts.length > 0 ? (
                  selectedInvestigation.investigation
                    .affected_accounts.map((username) => (
                      <span
                        className="account-tag"
                        key={username}
                      >
                        {username}
                      </span>
                    ))
                ) : (
                  <p>No matching accounts found.</p>
                )}
              </div>

              {/* RELATED LOGIN EVENTS */}

              <h4>Associated Login Activity</h4>

              {selectedInvestigation.investigation
                .related_events.length === 0 ? (
                <p>No related login events found.</p>
              ) : (
                selectedInvestigation.investigation
                  .related_events.map((event) => (
                    <div
                      className="data-row"
                      key={event.id}
                    >
                      <div>
                        <strong>{event.username}</strong>

                        <p className="investigation-event-id">
                          Event #{event.id}
                        </p>

                        <p>
                          {event.ip_address} —{' '}
                          {new Date(
                            event.timestamp
                          ).toLocaleString()}
                        </p>
                      </div>

                      <span
                        className={
                          event.status === 'failed'
                            ? 'login-failed'
                            : 'login-success'
                        }
                      >
                        {event.status.toUpperCase()}
                      </span>
                    </div>
                  ))
              )}

              {/* INVESTIGATION NOTES */}

              <div className="investigation-notes-section">
                <h4>Investigation Notes</h4>

                <p>
                  Document findings, actions taken, and
                  recommendations for this security alert.
                </p>

                <textarea
                  className="investigation-notes-input"
                  value={noteDraft}
                  onChange={(event) => {
                    setNoteDraft(event.target.value)
                    setNoteMessage('')
                    setNoteError('')
                  }}
                  placeholder={
                    'Enter investigation findings, ' +
                    'affected accounts, actions taken, ' +
                    'and recommended next steps...'
                  }
                  maxLength={10000}
                  rows={6}
                  disabled={noteSaving}
                />

                <div className="investigation-notes-actions">
                  <span>
                    {noteDraft.length.toLocaleString()} / 10,000
                    characters
                  </span>

                  <button
                    type="button"
                    className="save-notes-button"
                    onClick={() => void saveInvestigationNotes()}
                    disabled={noteSaving}
                  >
                    {noteSaving ? 'Saving...' : 'Save Notes'}
                  </button>
                </div>

                {noteMessage && (
                  <p className="simulation-feedback simulation-success">
                    ✓ {noteMessage}
                  </p>
                )}

                {noteError && (
                  <p
                    className="simulation-feedback simulation-failure"
                    role="alert"
                  >
                    {noteError}
                  </p>
                )}
              </div>


              {/* CORRELATION EXPLANATION */}

              <p className="investigation-note">
                {selectedInvestigation.investigation
                  .correlation_method === 'exact'
                  ? (
                    'These login events are directly linked ' +
                    'to this security alert through the ' +
                    'alert_events database table. ' +
                    'Only events associated with the ' +
                    'detection are displayed.'
                  )
                  : (
                    'This is a historical investigation. ' +
                    'Events were matched using the source ' +
                    'IP address, failed-login status, ' +
                    'and detection time window. ' +
                    'These relationships are inferred ' +
                    'rather than explicitly stored.'
                  )}
              </p>
            </div>
          )}
        </section>

        {/* ==================================
            LOGIN ACTIVITY
        ================================== */}

        <section className="panel" id="activity">
          <h2>Recent Login Activity</h2>
          <p>Search and filter security events.</p>


          <div className="export-actions">
            <a
              className="export-button"
              href={`${API_URL}/export/events`}
              download="sentinel_events.csv"
            >
              ↓ Export Events CSV
            </a>
          </div>


          <div style={{ marginTop: '22px' }}>
            <label
              htmlFor="ip-search"
              style={{
                display: 'block',
                color: '#91a2bc',
                fontSize: '13px',
                marginBottom: '10px'
              }}
            >
              Search by IP Address
            </label>

            <input
              id="ip-search"
              type="text"
              value={ipSearch}
              onChange={(event) =>
                setIpSearch(event.target.value)
              }
              placeholder="Enter an IP address (e.g. 192.0.2.45)"
            />
          </div>

          <div className="filter-buttons">
            <button
              className={eventFilter === 'all' ? 'selected' : ''}
              onClick={() => setEventFilter('all')}
            >
              All Events
            </button>

            <button
              className={eventFilter === 'failed' ? 'selected' : ''}
              onClick={() => setEventFilter('failed')}
            >
              Failed Logins
            </button>

            <button
              className={eventFilter === 'success' ? 'selected' : ''}
              onClick={() => setEventFilter('success')}
            >
              Successful Logins
            </button>
          </div>

          <div className="event-count">
            Showing {Math.min(filteredEvents.length, 8)} of{' '}
            {filteredEvents.length} matching events
          </div>

          {filteredEvents.length === 0 ? (
            <p>No matching login events found.</p>
          ) : (
            filteredEvents.slice(0, 8).map((event) => (
              <div className="data-row" key={event.id}>
                <div>
                  <strong>{event.username}</strong>

                  <p>
                    {event.ip_address} —{' '}
                    {new Date(
                      event.timestamp
                    ).toLocaleString()}
                  </p>
                </div>

                <span
                  className={
                    event.status === 'failed'
                      ? 'login-failed'
                      : 'login-success'
                  }
                >
                  {event.status.toUpperCase()}
                </span>
              </div>
            ))
          )}
        </section>
      </main>
    </div>
  )
}

export default App
