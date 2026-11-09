import AdvancedFeatures from './AdvancedFeatures'
import AssessmentWorkspace from './AssessmentWorkspace'
import { useEffect, useMemo, useState } from 'react'
import './App.css'

type TargetType = 'ip' | 'cidr' | 'domain' | 'hostname' | 'url'
type Target = { type: TargetType; value: string; reason?: string }
type ScopeDocument = {
  scope_version: '1.0'; engagement_name: string; client_organization?: string; description?: string
  authorization: { status: 'ACTIVE'; authorized_by: string; valid_from: string; valid_until: string }
  targets: { allowed: Target[]; excluded: Target[] }
  operations: { allowed: string[]; prohibited: string[] }
  constraints: { max_scan_rate: number; max_concurrent_scans: number; testing_hours?: string; allow_exploitation: boolean; allow_destructive_operations: boolean; allow_external_callbacks: boolean; allow_authentication_testing: boolean }
}
type Project = { id: string; name: string; description?: string }
type Revision = { id: string; project_id: string; version: number; status: string; document: ScopeDocument; validated_at?: string; activated_at?: string }
type ValidationError = { location: (string | number)[]; message: string; type: string }

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const operationOptions = [
  ['nmap.service_discovery', 'Network service discovery', 'Nmap'],
  ['httpx.web_probe', 'HTTP service probing', 'HTTPX'],
  ['nikto.server_audit', 'Web server auditing', 'Nikto'],
  ['nuclei.template_scan', 'Template-based vulnerability scanning', 'Nuclei'],
  ['zap.web_scan', 'Web application scanning', 'OWASP ZAP'],
  ['nessus.vulnerability_scan', 'Vulnerability scanning', 'Nessus'],
  ['authentication.login_test', 'Authentication testing', 'Authorized login testing'],
  ['metasploit.exploitation', 'Exploitation', 'Metasploit'],
  ['dos.attack', 'Denial-of-service testing', 'DoS'],
  ['data.exfiltration', 'Data extraction / exfiltration', 'Data extraction'],
]
const isoLocal = (date: Date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
const initialDocument = (): ScopeDocument => {
  const now = new Date(); const end = new Date(now); end.setDate(end.getDate() + 7)
  return { scope_version: '1.0', engagement_name: '', client_organization: '', description: '', authorization: { status: 'ACTIVE', authorized_by: '', valid_from: isoLocal(now), valid_until: isoLocal(end) }, targets: { allowed: [], excluded: [] }, operations: { allowed: [], prohibited: ['metasploit.exploitation', 'dos.attack', 'data.exfiltration'] }, constraints: { max_scan_rate: 5, max_concurrent_scans: 2, testing_hours: '', allow_exploitation: false, allow_destructive_operations: false, allow_external_callbacks: false, allow_authentication_testing: false } }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) } })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || JSON.stringify(data.detail || data))
  return data as T
}

function ScopeApp({ onIntegrations, onAssessment }: { onIntegrations?: () => void; onAssessment?: () => void } = {}) {
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState('')
  const [projectName, setProjectName] = useState('')
  const [creatingProject, setCreatingProject] = useState(false)
  const [document, setDocument] = useState<ScopeDocument>(initialDocument)
  const [mode, setMode] = useState<'guided' | 'json'>('guided')
  const [jsonText, setJsonText] = useState('')
  const [errors, setErrors] = useState<ValidationError[]>([])
  const [message, setMessage] = useState('')
  const [revision, setRevision] = useState<Revision | null>(null)
  const [active, setActive] = useState<Revision | null>(null)
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState(0)

  const selectedProject = useMemo(() => projects.find(p => p.id === projectId), [projects, projectId])
  const loadProjects = async () => {
    const rows = await request<Project[]>('/projects'); setProjects(rows)
    if (!projectId && rows.length) setProjectId(rows[0].id)
  }
  const loadScope = async (id: string) => {
    if (!id) return
    const result = await request<{ active: Revision | null; latest: Revision | null }>(`/projects/${id}/scope`)
    setActive(result.active); setRevision(result.latest)
    if (result.latest?.document) { setDocument(result.latest.document); setJsonText(JSON.stringify(result.latest.document, null, 2)) }
    else { const fresh = initialDocument(); setDocument(fresh); setJsonText(JSON.stringify(fresh, null, 2)) }
    setErrors([]); setMessage('')
  }
  useEffect(() => { loadProjects().catch(e => setMessage(e.message)) }, [])
  useEffect(() => { if (projectId) loadScope(projectId).catch(e => setMessage(e.message)) }, [projectId])

  const update = (path: string, value: unknown) => {
    setDocument(prev => {
      const next = structuredClone(prev) as any; const keys = path.split('.'); let cursor = next
      keys.slice(0, -1).forEach(key => { cursor = cursor[key] }); cursor[keys[keys.length - 1]] = value
      setJsonText(JSON.stringify(next, null, 2)); return next
    })
  }
  const addTarget = (list: 'allowed' | 'excluded') => update(`targets.${list}`, [...document.targets[list], { type: 'ip', value: '' }])
  const editTarget = (list: 'allowed' | 'excluded', index: number, key: keyof Target, value: string) => {
    const next = [...document.targets[list]]
    const current = next[index]
    // A slash is unambiguous CIDR notation. Auto-select the CIDR target type
    // so users do not accidentally submit a network as a single IP address.
    const inferredType = key === 'value' && value.includes('/')
      ? 'cidr'
      : current.type
    next[index] = { ...current, [key]: value, type: inferredType }
    update(`targets.${list}`, next)
  }
  const removeTarget = (list: 'allowed' | 'excluded', index: number) => update(`targets.${list}`, document.targets[list].filter((_, i) => i !== index))
  const toggleOperation = (key: string, checked: boolean, list: 'allowed' | 'prohibited') => {
    const other = list === 'allowed' ? 'prohibited' : 'allowed'
    update(`operations.${list}`, checked ? [...document.operations[list], key] : document.operations[list].filter(v => v !== key))
    update(`operations.${other}`, document.operations[other].filter(v => v !== key))
  }
  const makeProject = async () => {
    if (!projectName.trim()) return
    setBusy(true)
    try { const row = await request<Project>('/projects', { method: 'POST', body: JSON.stringify({ name: projectName.trim(), description: '', authorization: {} }) }); await loadProjects(); setProjectId(row.id); setProjectName(''); setCreatingProject(false); setMessage('Project created. Configure its engagement scope before assessment.') }
    catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }
  const getDocument = () => {
    if (mode === 'json') return JSON.parse(jsonText) as ScopeDocument
    return { ...document, authorization: { ...document.authorization, valid_from: new Date(document.authorization.valid_from).toISOString(), valid_until: new Date(document.authorization.valid_until).toISOString() } }
  }
  const validate = async () => {
    if (!projectId) return
    setBusy(true); setErrors([]); setMessage('')
    try {
      const candidate = getDocument()
      const result = await request<{ valid: boolean; document: ScopeDocument; errors: ValidationError[] }>(`/projects/${projectId}/scope/validate`, { method: 'POST', body: JSON.stringify({ document: candidate }) })
      if (!result.valid) { setErrors(result.errors); setMessage('Validation failed. Correct the issues below.'); return }
      setDocument(result.document); setJsonText(JSON.stringify(result.document, null, 2))
      const draft = await request<Revision>(`/projects/${projectId}/scope/draft`, { method: 'POST', body: JSON.stringify({ document: result.document, created_by: 'human' }) })
      const saved = await request<Revision>(`/projects/${projectId}/scope/${draft.id}/validate`, { method: 'POST' })
      setRevision(saved); setMessage(`Scope v${saved.version} validated and saved as a draft. It is not active yet.`)
      setStep(5)
    } catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }
  const activate = async () => {
    if (!projectId || !revision) return
    if (!window.confirm(`Activate scope revision v${revision.version} for this project? This will supersede the currently active revision.`)) return
    setBusy(true)
    try { const row = await request<Revision>(`/projects/${projectId}/scope/activate`, { method: 'POST', body: JSON.stringify({ revision_id: revision.id, confirmed: true }) }); setRevision(row); setActive(row); setMessage(`Scope v${row.version} is now ACTIVE.`) }
    catch (e) { setMessage((e as Error).message) } finally { setBusy(false) }
  }
  const importFile = async (file?: File) => { if (!file) return; try { const text = await file.text(); const parsed = JSON.parse(text); setJsonText(JSON.stringify(parsed, null, 2)); setMode('json'); setErrors([]); setMessage('JSON loaded. Run validation to check the SENTINEL scope schema.') } catch { setMessage('The selected file is not valid JSON.') } }

  const steps = ['Engagement', 'Authorization', 'Targets', 'Operations', 'Constraints', 'Review']
  const targetEditor = (list: 'allowed' | 'excluded', title: string, hint: string) => <section className="scope-card"><div className="card-heading"><div><h3>{title}</h3><p>{hint} Use CIDR notation for ranges (for example, 192.168.0.0/16); the target type switches automatically when you enter '/'.</p></div><button className="button secondary small" onClick={() => addTarget(list)}>＋ Add target</button></div>{document.targets[list].map((target, index) => <div className="target-row" key={`${list}-${index}`}><select value={target.type} onChange={e => editTarget(list, index, 'type', e.target.value)}><option value="ip">IP address</option><option value="cidr">CIDR range</option><option value="domain">Domain</option><option value="hostname">Hostname</option><option value="url">URL</option></select><input value={target.value} placeholder={target.type === 'cidr' ? '192.168.1.0/24' : '192.168.1.10'} onChange={e => editTarget(list, index, 'value', e.target.value)} /><input className="reason" value={target.reason || ''} placeholder="Reason (optional)" onChange={e => editTarget(list, index, 'reason', e.target.value)} /><button className="icon-button" title="Remove target" onClick={() => removeTarget(list, index)}>×</button></div>)}{!document.targets[list].length && <div className="empty-inline">No targets added yet.</div>}</section>

  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">S</div><div><strong>SENTINEL</strong><span>ASSESSMENT PLATFORM</span></div></div><div className="side-label">WORKSPACE</div><div className="nav-item active"><span>▦</span> Projects & scope</div><button className="nav-item" onClick={onIntegrations}><span>⌘</span> Tool integrations</button><button className="nav-item" onClick={onAssessment}><span>◈</span> Assessment operations</button><div className="side-footer"><span className="status-dot"/> Systems operational <small>Scope Builder · v1.0</small></div></aside>
    <main className="main-content"><header className="topbar"><div><span className="eyebrow">ENGAGEMENT MANAGEMENT</span><h1>Scope configuration</h1></div><div className="top-right"><span className="secure-pill">⌑ Deterministic policy</span><span className="avatar">OP</span></div></header>
      <div className="content-wrap"><div className="page-intro"><div><div className="breadcrumb">Projects <span>/</span> {selectedProject?.name || 'Select a project'} <span>/</span> Scope</div><h2>Define the boundaries of your assessment.</h2><p>Every assessment action must be explicitly authorized by this project's active scope.</p></div><div className="scope-state"><span className={`state-dot ${active ? 'green' : 'amber'}`}/><div><strong>{active ? `SCOPE v${active.version} ACTIVE` : 'NO ACTIVE SCOPE'}</strong><small>{active ? 'Authorization configured' : 'Assessment execution should remain disabled'}</small></div></div></div>
      <div className="project-bar"><div className="project-select"><label>PROJECT</label><select value={projectId} onChange={e => setProjectId(e.target.value)}><option value="">Select project</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></div><button className="button secondary" onClick={() => setCreatingProject(v => !v)}>＋ New project</button>{creatingProject && <div className="new-project"><input value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="Project name" onKeyDown={e => e.key === 'Enter' && makeProject()} /><button className="button primary" disabled={busy || !projectName.trim()} onClick={makeProject}>Create</button></div>}</div>
      {!projectId ? <div className="empty-state"><div className="empty-icon">⌂</div><h3>Select or create a project</h3><p>A scope document is created and maintained separately for each project.</p></div> : <>
      <div className="mode-switch"><button className={mode === 'guided' ? 'selected' : ''} onClick={() => { setMode('guided'); setErrors([]) }}><span>☷</span><strong>Guided setup</strong><small>Build scope through a questionnaire</small></button><button className={mode === 'json' ? 'selected' : ''} onClick={() => { setMode('json'); setJsonText(JSON.stringify(document, null, 2)); setErrors([]) }}><span>{'{ }'}</span><strong>Manual JSON</strong><small>Import or edit a scope document</small></button></div>
      {mode === 'guided' ? <div className="builder-layout"><nav className="step-nav">{steps.map((label, i) => <button key={label} className={step === i ? 'current' : step > i ? 'completed' : ''} onClick={() => setStep(i)}><span>{step > i ? '✓' : String(i + 1).padStart(2, '0')}</span>{label}</button>)}</nav><div className="builder-panel">
        {step === 0 && <><div className="section-kicker">01 / ENGAGEMENT</div><h2>What are we assessing?</h2><p className="section-copy">Identify the engagement. This information is stored with the project's scope revision.</p><label>Engagement name <em>Required</em><input value={document.engagement_name} onChange={e => update('engagement_name', e.target.value)} placeholder="e.g. External infrastructure assessment" /></label><label>Client / organization<input value={document.client_organization || ''} onChange={e => update('client_organization', e.target.value)} placeholder="Organization name" /></label><label>Description<textarea value={document.description || ''} onChange={e => update('description', e.target.value)} placeholder="Assessment purpose and context" rows={3}/></label></>}
        {step === 1 && <><div className="section-kicker">02 / AUTHORIZATION</div><h2>Who authorized this assessment?</h2><p className="section-copy">An active scope requires an authorizing party and a valid authorization window.</p><label>Authorized by <em>Required</em><input value={document.authorization.authorized_by} onChange={e => update('authorization.authorized_by', e.target.value)} placeholder="Name or role of authorizing party" /></label><div className="form-grid"><label>Valid from<input type="datetime-local" value={document.authorization.valid_from} onChange={e => update('authorization.valid_from', e.target.value)} /></label><label>Valid until<input type="datetime-local" value={document.authorization.valid_until} onChange={e => update('authorization.valid_until', e.target.value)} /></label></div><div className="notice">Authorization dates are checked again during activation and must include the current time.</div></>}
        {step === 2 && <><div className="section-kicker">03 / TARGETS</div><h2>Where may SENTINEL operate?</h2><p className="section-copy">Only explicitly allowed targets are in scope. Exclusions take precedence over inclusions.</p>{targetEditor('allowed', 'Authorized targets', 'Add individual hosts, CIDR ranges, domains, hostnames or URLs.')}{targetEditor('excluded', 'Explicit exclusions', 'These targets are blocked even if they fall inside an allowed range.')}</>}
        {step === 3 && <><div className="section-kicker">04 / OPERATIONS</div><h2>Which operations are permitted?</h2><p className="section-copy">Nothing is permitted by default. Select the exact operation identifiers this engagement allows.</p><div className="operation-list">{operationOptions.map(([key, label, tool]) => <div className="operation-row" key={key}><div><strong>{label}</strong><small>{tool} · <code>{key}</code></small></div><label className="check-wrap"><input type="checkbox" checked={document.operations.allowed.includes(key)} onChange={e => toggleOperation(key, e.target.checked, 'allowed')}/><span>Allow</span></label><label className="check-wrap prohibited"><input type="checkbox" checked={document.operations.prohibited.includes(key)} onChange={e => toggleOperation(key, e.target.checked, 'prohibited')}/><span>Prohibit</span></label></div>)}</div><div className="notice">An operation not explicitly allowed is denied, even if it is not listed under prohibited operations.</div></>}
        {step === 4 && <><div className="section-kicker">05 / CONSTRAINTS</div><h2>Set operational limits.</h2><p className="section-copy">These constraints further restrict otherwise permitted operations.</p><div className="form-grid"><label>Maximum scan rate (requests/sec)<input type="number" min="1" max="1000" value={document.constraints.max_scan_rate} onChange={e => update('constraints.max_scan_rate', Number(e.target.value))}/></label><label>Maximum concurrent scans<input type="number" min="1" max="100" value={document.constraints.max_concurrent_scans} onChange={e => update('constraints.max_concurrent_scans', Number(e.target.value))}/></label></div><label>Permitted testing hours <small className="muted-inline">Optional, e.g. Mon-Fri 09:00-17:00 UTC</small><input value={document.constraints.testing_hours || ''} onChange={e => update('constraints.testing_hours', e.target.value)} placeholder="No schedule specified"/></label><div className="toggle-list">{([['allow_authentication_testing','Authentication testing'],['allow_exploitation','Exploitation'],['allow_destructive_operations','Destructive operations'],['allow_external_callbacks','External callbacks / OAST']] as const).map(([key, label]) => <label className="toggle-row" key={key}><span>{label}</span><input type="checkbox" checked={document.constraints[key]} onChange={e => update(`constraints.${key}`, e.target.checked)}/></label>)}</div><div className="notice warning">Enabling a high-impact capability here does not automatically permit it. The corresponding operation must also be explicitly allowed, and the gate must enforce both conditions.</div></>}
        {step === 5 && <><div className="section-kicker">06 / REVIEW</div><h2>Review the engagement scope.</h2><p className="section-copy">Check the authorization and boundaries before saving and activating this revision.</p><div className="review-grid"><div><small>ENGAGEMENT</small><strong>{document.engagement_name || '—'}</strong></div><div><small>AUTHORIZED BY</small><strong>{document.authorization.authorized_by || '—'}</strong></div><div><small>ALLOWED TARGETS</small><strong>{document.targets.allowed.length}</strong></div><div><small>EXCLUDED TARGETS</small><strong>{document.targets.excluded.length}</strong></div><div><small>PERMITTED OPERATIONS</small><strong>{document.operations.allowed.length}</strong></div><div><small>PROHIBITED OPERATIONS</small><strong>{document.operations.prohibited.length}</strong></div></div><details><summary>Inspect generated JSON</summary><pre>{JSON.stringify(document, null, 2)}</pre></details><div className="notice">Validation saves a new immutable draft revision. Activation is a separate, explicitly confirmed action.</div></>}
        <div className="builder-actions"><button className="button secondary" disabled={step === 0} onClick={() => setStep(s => Math.max(0, s - 1))}>Back</button><div>{step < 5 ? <button className="button primary" onClick={() => setStep(s => Math.min(5, s + 1))}>Continue <span>→</span></button> : <button className="button primary" disabled={busy} onClick={validate}>{busy ? 'Validating…' : 'Validate & save draft'}</button>}</div></div>
      </div></div> : <div className="json-panel"><div className="json-toolbar"><div><h3>Scope document JSON</h3><p>Schema version 1.0 · Strict validation · Unknown fields rejected</p></div><label className="button secondary small upload-button">↑ Import .json<input type="file" accept="application/json,.json" onChange={e => importFile(e.target.files?.[0])}/></label></div><textarea className="json-editor" spellCheck={false} value={jsonText} onChange={e => setJsonText(e.target.value)} /><div className="json-footer"><span>Edits are not saved until validation succeeds.</span><button className="button primary" disabled={busy} onClick={validate}>{busy ? 'Validating…' : 'Validate & save draft'}</button></div></div>}
      {errors.length > 0 && <div className="validation-errors"><strong>Validation failed · {errors.length} issue(s)</strong>{errors.map((error, i) => <div key={i}><code>{error.location.join('.') || 'document'}</code><span>{error.message}</span></div>)}</div>}
      {message && <div className={`toast ${errors.length ? 'error' : ''}`}>{message}</div>}
      <div className="revision-bar"><div><span className="revision-icon">▤</span><div><strong>{revision ? `Latest revision · v${revision.version} · ${revision.status}` : 'No saved scope revision'}</strong><small>{active ? `Active since ${new Date(active.activated_at || '').toLocaleString()}` : 'Create and activate a scope before assessment execution.'}</small></div></div><button className="button activate" disabled={!revision || revision.status === 'ACTIVE' || busy} onClick={activate}>Activate scope →</button></div>
      </>}
      <footer> S E N T I N E L <span>·</span> Engagement authorization is enforced server-side.</footer></div>
    </main>
  </div>
}



type IntegrationVersion = {
  id: string; version: string; image_reference: string; manifest_sha256: string;
  validation_status: string; runtime_validation_status: string; created_at?: string;
}
type Integration = {
  id: string; tool_id: string; display_name: string; description: string;
  current_version: string; enabled: boolean; created_by: string; created_at?: string;
  version: (IntegrationVersion & { manifest: Record<string, any> }) | null;
  execution_ready: boolean; execution_block_reason?: string;
}
type Capability = {
  tool: string; action: string; description: string; source: string;
  integration_id: string; integration_version: string; manifest_sha256: string;
  capabilities: string[]; parameters: Record<string, any>; executable: boolean;
  execution_block_reason?: string;
}
type ApiIssue = { path: string; message: string; hint?: string }
type ApiFailure = Error & { status?: number; issues?: ApiIssue[]; raw?: string }

const starterManifest = `manifest_version: "1.0"
tool_id: subfinder
name: Subfinder
version: "1.0.0"
description: Passive subdomain enumeration using configured sources.

runtime:
  type: container
  image: "registry.example.com/security/subfinder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  entrypoint:
    - "-d"
    - "{{target}}"
  timeout_seconds: 300
  memory_mb: 512
  cpus: 1.0
  read_only_rootfs: true
  network_access: scoped_targets_only

capabilities:
  - subdomain_enumeration
  - passive_reconnaissance

operations:
  enumerate:
    description: Enumerate subdomains for a domain.
    parameters:
      target:
        type: string
        description: Domain to enumerate.
        required: true

output_format: json
output_schema_version: "1.0"
`

function parseApiFailure(error: unknown): ApiFailure {
  if (error instanceof Error && 'status' in error) return error as ApiFailure
  return Object.assign(new Error(error instanceof Error ? error.message : 'Unexpected error'), {})
}
function issueHints(message: string): string | undefined {
  if (/sha256|digest|immutable/i.test(message)) return 'Pin the container image to an immutable @sha256:<64 hexadecimal characters> digest.'
  if (/read_only_rootfs/i.test(message)) return 'Set runtime.read_only_rootfs to true.'
  if (/extra inputs are not permitted/i.test(message)) return 'Remove the unsupported field or check the manifest schema.'
  if (/field required|missing/i.test(message)) return 'Add the required field using the exact schema name.'
  if (/valid dictionary/i.test(message)) return 'Use a YAML mapping (key: value), not a list, for this field.'
  if (/tool_id/i.test(message)) return 'Use 3–80 lowercase snake_case characters, starting with a letter.'
  return undefined
}
async function integrationRequest<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) },
    })
  } catch {
    throw Object.assign(new Error(`Could not reach the SENTINEL API at ${API}. Check that the backend is running and the frontend can reach it.`), { status: 0, issues: [] }) as ApiFailure
  }
  const raw = await response.text()
  let data: any = {}
  try { data = raw ? JSON.parse(raw) : {} } catch { data = { detail: raw } }
  if (!response.ok) {
    const detail = data?.detail
    const issues: ApiIssue[] = []
    if (Array.isArray(detail)) {
      detail.forEach((item: any) => issues.push({
        path: Array.isArray(item.loc) ? item.loc.filter((part: any) => part !== 'body').join('.') || 'request' : 'request',
        message: item.msg || 'Validation error',
        hint: issueHints(item.msg || ''),
      }))
    } else if (typeof detail === 'string') {
      // The manifest service currently returns Pydantic's formatted validation text as a string.
      const lines = detail.split('\n').map((line: string) => line.trim()).filter(Boolean)
      const fieldLines = lines.filter((line: string) => /^[A-Za-z_][A-Za-z0-9_.\[\]-]*$/.test(line))
      if (fieldLines.length) {
        fieldLines.forEach((field: string, index: number) => {
          const next = lines.slice(lines.indexOf(field) + 1).find((line: string) => !/^\s*$/.test(line))
          if (next && !/^(input_value=|input_type=|For further information)/.test(next))
            issues.push({ path: field, message: next.replace(/\s*\[type=.*$/, ''), hint: issueHints(next) })
        })
      }
    }
    const message = typeof detail === 'string' ? detail : detail?.message || `Request failed with HTTP ${response.status}`
    throw Object.assign(new Error(message), { status: response.status, issues, raw }) as ApiFailure
  }
  return data as T
}

function IntegrationConsole() {
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [capabilities, setCapabilities] = useState<Capability[]>([])
  const [executionReady, setExecutionReady] = useState(false)
  const [selectedId, setSelectedId] = useState('')
  const [versions, setVersions] = useState<IntegrationVersion[]>([])
  const [manifestYaml, setManifestYaml] = useState(starterManifest)
  const [createdBy, setCreatedBy] = useState('local-user')
  const [filter, setFilter] = useState('')
  const [view, setView] = useState<'catalogue' | 'register' | 'capabilities'>('catalogue')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiFailure | null>(null)
  const [notice, setNotice] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [showRawError, setShowRawError] = useState(false)

  const selected = integrations.find(item => item.id === selectedId) || null
  const refresh = async (keepSelection = true) => {
    setLoading(true); setError(null)
    try {
      const [list, caps] = await Promise.all([
        integrationRequest<{ integrations: Integration[] }>('/integrations'),
        integrationRequest<{ capabilities: Capability[]; execution_ready: boolean }>('/integrations/capabilities'),
      ])
      setIntegrations(list.integrations || [])
      setCapabilities(caps.capabilities || [])
      setExecutionReady(Boolean(caps.execution_ready))
      if (!keepSelection || !list.integrations.some(item => item.id === selectedId))
        setSelectedId(list.integrations[0]?.id || '')
      setLastUpdated(new Date())
    } catch (e) { setError(parseApiFailure(e)) }
    finally { setLoading(false) }
  }
  useEffect(() => { void refresh(false) }, [])
  useEffect(() => {
    if (!selectedId) { setVersions([]); return }
    let cancelled = false
    integrationRequest<{ versions: IntegrationVersion[] }>(`/integrations/${selectedId}/versions`)
      .then(data => { if (!cancelled) setVersions(data.versions || []) })
      .catch(e => { if (!cancelled) setError(parseApiFailure(e)) })
    return () => { cancelled = true }
  }, [selectedId, integrations.length])

  const register = async () => {
    setBusy(true); setError(null); setNotice(''); setShowRawError(false)
    try {
      const result = await integrationRequest<Integration>('/integrations/register', {
        method: 'POST', body: JSON.stringify({ manifest_yaml: manifestYaml, created_by: createdBy.trim() || 'local-user' }),
      })
      setNotice(`${result.display_name} v${result.current_version} registered. Manifest validation passed; runtime validation is still pending.`)
      await refresh(false)
      setSelectedId(result.id); setView('catalogue')
    } catch (e) { setError(parseApiFailure(e)) }
    finally { setBusy(false) }
  }
  const setEnabled = async (integration: Integration, enabled: boolean) => {
    setBusy(true); setError(null); setNotice('')
    try {
      const result = await integrationRequest<Integration>(`/integrations/${integration.id}/${enabled ? 'enable' : 'disable'}`, {
        method: 'POST', body: JSON.stringify({ enabled_by: 'local-user' }),
      })
      setNotice(`${result.display_name} ${enabled ? 'enabled' : 'disabled'}.`)
      await refresh()
    } catch (e) { setError(parseApiFailure(e)) }
    finally { setBusy(false) }
  }
  const importManifest = async (file?: File) => {
    if (!file) return
    if (file.size > 100_000) { setError(Object.assign(new Error('Manifest file exceeds the 100 KB API limit.'), { status: 413, issues: [] })); return }
    setManifestYaml(await file.text()); setError(null); setNotice(`Loaded ${file.name}. The backend will perform authoritative YAML and schema validation.`)
  }
  const filtered = integrations.filter(item => `${item.display_name} ${item.tool_id} ${item.description}`.toLowerCase().includes(filter.toLowerCase()))
  const copy = async (value: string) => { try { await navigator.clipboard.writeText(value); setNotice('Copied to clipboard.') } catch { setNotice('Clipboard access was denied by the browser.') } }

  return <div className="tif-page">
    <div className="tif-heading">
      <div><div className="tif-eyebrow">EXTENSIBILITY / TOOL INTEGRATION FRAMEWORK</div><h2>Tool integrations</h2><p>Register versioned tool manifests and inspect the capabilities SENTINEL can discover.</p></div>
      <div className="tif-heading-actions"><span className={`tif-health ${error?.status === 0 ? 'down' : 'up'}`}><i/> {error?.status === 0 ? 'API unreachable' : 'API connection'}</span><button className="tif-button ghost" onClick={() => refresh()} disabled={loading}>↻ Refresh</button></div>
    </div>

    <div className="tif-readiness">
      <div className="tif-readiness-icon">◇</div><div className="tif-readiness-copy"><strong>{executionReady ? 'Execution services report ready' : 'Container execution is not configured'}</strong><span>{executionReady ? 'The capability API reports execution readiness.' : 'Manifests can be registered and inspected. Execution remains blocked until an isolated runner and runtime validation are implemented.'}</span></div>
      <span className="tif-status-pill blocked">EXECUTION BLOCKED</span>
    </div>

    <div className="tif-stats">
      <div><span>REGISTERED TOOLS</span><strong>{integrations.length}</strong><small>Persistent integrations</small></div>
      <div><span>VERSIONS</span><strong>{integrations.reduce((sum, item) => sum + (item.version ? 1 : 0), 0)}</strong><small>Current versions represented</small></div>
      <div><span>DISCOVERED CAPABILITIES</span><strong>{capabilities.length}</strong><small>Enabled integrations only</small></div>
      <div><span>EXECUTION READY</span><strong className="tif-no">0</strong><small>Runner unavailable</small></div>
    </div>

    {error && <div className="tif-alert error" role="alert">
      <div className="tif-alert-title"><span>⚠</span><div><strong>Request failed{error.status ? ` · HTTP ${error.status}` : ''}</strong><small>{error.message}</small></div><button onClick={() => setError(null)} aria-label="Dismiss error">×</button></div>
      {error.issues?.length ? <div className="tif-issues"><strong>{error.issues.length} validation detail(s)</strong>{error.issues.map((issue, i) => <div className="tif-issue" key={`${issue.path}-${i}`}><code>{issue.path}</code><span>{issue.message}{issue.hint && <small>Suggested fix: {issue.hint}</small>}</span></div>)}</div> : null}
      {error.raw && <details className="tif-raw"><summary>Show raw response</summary><pre>{error.raw}</pre></details>}
      {error.status === 0 && <div className="tif-help">Check <code>docker compose ps</code>, backend logs, and the configured API base URL: <code>{API}</code>.</div>}
    </div>}
    {notice && <div className="tif-alert success" role="status"><span>✓</span>{notice}<button onClick={() => setNotice('')} aria-label="Dismiss message">×</button></div>}

    <div className="tif-tabs">
      <button className={view === 'catalogue' ? 'active' : ''} onClick={() => setView('catalogue')}>▤ Integrations <b>{integrations.length}</b></button>
      <button className={view === 'register' ? 'active' : ''} onClick={() => { setView('register'); setError(null) }}>＋ Register tool</button>
      <button className={view === 'capabilities' ? 'active' : ''} onClick={() => setView('capabilities')}>⌘ Capabilities <b>{capabilities.length}</b></button>
    </div>

    {view === 'register' && <section className="tif-register">
      <div className="tif-section-head"><div><span className="tif-kicker">NEW INTEGRATION</span><h3>Register a tool manifest</h3><p>Paste YAML or import a .yaml/.yml file. Validation and persistence happen on the backend.</p></div><label className="tif-button ghost file-pick">↑ Import YAML<input type="file" accept=".yaml,.yml,text/yaml,text/plain" onChange={e => importManifest(e.target.files?.[0])}/></label></div>
      <div className="tif-register-meta"><label>Registered by<input value={createdBy} onChange={e => setCreatedBy(e.target.value)} maxLength={120}/></label><span>Maximum manifest size: 100 KB</span></div>
      <textarea className="tif-yaml" spellCheck={false} value={manifestYaml} onChange={e => { setManifestYaml(e.target.value); setError(null) }} aria-label="Tool manifest YAML"/>
      <div className="tif-editor-foot"><span>Schema v1.0 · strict fields · immutable image digest required</span><button className="tif-button primary" onClick={register} disabled={busy || !manifestYaml.trim()}>{busy ? 'Registering…' : 'Validate & register tool →'}</button></div>
      <div className="tif-note"><strong>Manifest safety</strong><span>Registration stores a declarative manifest only. It does not pull or execute the container image. Never place secrets, credentials, or private keys in a manifest.</span></div>
    </section>}

    {view === 'catalogue' && <div className="tif-catalogue">
      <div className="tif-list-panel">
        <div className="tif-list-head"><div><h3>Registered integrations</h3><small>{loading ? 'Refreshing catalogue…' : `${integrations.length} integration(s) in registry`}</small></div><input value={filter} onChange={e => setFilter(e.target.value)} placeholder="⌕  Search tools"/></div>
        {loading && <div className="tif-skeleton">Loading integration registry…</div>}
        {!loading && !filtered.length && <div className="tif-empty"><div>◇</div><strong>{integrations.length ? 'No matching integrations' : 'No integrations registered'}</strong><p>{integrations.length ? 'Try another search term.' : 'Register your first YAML manifest to add a tool to the catalogue.'}</p>{!integrations.length && <button className="tif-button primary" onClick={() => setView('register')}>Register first tool</button>}</div>}
        {filtered.map(item => <button className={`tif-tool-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelectedId(item.id)}>
          <span className="tif-tool-icon">⌘</span><span className="tif-tool-main"><strong>{item.display_name}</strong><small>{item.tool_id} · v{item.current_version}</small></span><span className="tif-mini-status">{item.version?.validation_status || 'UNKNOWN'}</span>
        </button>)}
      </div>
      <div className="tif-detail-panel">
        {!selected ? <div className="tif-empty detail-empty"><div>↖</div><strong>Select an integration</strong><p>Choose a tool from the catalogue to inspect its manifest, version and runtime state.</p></div> : <>
          <div className="tif-detail-title"><div><span className="tif-kicker">INTEGRATION DETAIL</span><h3>{selected.display_name}</h3><p>{selected.description}</p></div><span className="tif-status-pill registered">REGISTERED</span></div>
          <div className="tif-detail-meta"><div><small>TOOL ID</small><strong>{selected.tool_id}</strong></div><div><small>CURRENT VERSION</small><strong>v{selected.current_version}</strong></div><div><small>ENABLED</small><strong>{selected.enabled ? 'Yes' : 'No'}</strong></div></div>
          <div className="tif-runtime-box"><div><span className="tif-runtime-mark">◈</span><div><strong>Runtime validation</strong><small>{selected.version?.runtime_validation_status || 'Not available'}</small></div></div><span className="tif-status-pill blocked">PENDING RUNNER</span><p>{selected.execution_block_reason || 'Execution is not available.'}</p></div>
          <div className="tif-manifest-head"><h4>Current manifest</h4><button className="tif-text-button" onClick={() => selected.version && copy(JSON.stringify(selected.version.manifest, null, 2))}>Copy JSON</button></div>
          <pre className="tif-manifest-view">{selected.version ? JSON.stringify(selected.version.manifest, null, 2) : 'No manifest version is available.'}</pre>
          <div className="tif-hash"><span>MANIFEST SHA-256</span><code>{selected.version?.manifest_sha256 || 'Unavailable'}</code><button onClick={() => selected.version && copy(selected.version.manifest_sha256)}>Copy</button></div>
          <div className="tif-version-head"><h4>Version history</h4><span>{versions.length} version(s)</span></div>
          {versions.map(version => <div className="tif-version-row" key={version.id}><div><strong>v{version.version}</strong><small>{version.validation_status} · {version.runtime_validation_status}</small></div><code>{version.manifest_sha256.slice(0, 16)}…</code><time>{version.created_at ? new Date(version.created_at).toLocaleDateString() : '—'}</time></div>)}
          <div className="tif-actions"><button className="tif-button ghost" disabled={busy || !selected.enabled} onClick={() => setEnabled(selected, false)}>Disable integration</button><button className="tif-button blocked-action" disabled title="Runner and runtime validation are not implemented">Enable unavailable · runner pending</button></div>
        </>}
      </div>
    </div>}

    {view === 'capabilities' && <section className="tif-capabilities">
      <div className="tif-section-head"><div><span className="tif-kicker">DISCOVERY INDEX</span><h3>Capability explorer</h3><p>Only enabled integrations are returned by the current backend capability endpoint.</p></div><span className={`tif-status-pill ${capabilities.length ? 'registered' : 'blocked'}`}>{capabilities.length} DISCOVERED</span></div>
      {!capabilities.length ? <div className="tif-empty"><div>⌘</div><strong>No capabilities currently discoverable</strong><p>Registered tools are stored, but the backend only exposes capabilities for enabled integrations. Enabling is intentionally blocked until the isolated runner is available.</p><button className="tif-button ghost" onClick={() => setView('catalogue')}>View registered integrations</button></div> :
        <div className="tif-cap-list">{capabilities.map((cap, i) => <article className="tif-cap-card" key={`${cap.integration_id}-${cap.action}-${i}`}><div><span className="tif-cap-tag">{cap.tool}</span><h4>{cap.action}</h4><p>{cap.description}</p><small>v{cap.integration_version} · {cap.source}</small></div><span className="tif-status-pill blocked">NOT EXECUTABLE</span><details><summary>Parameters & provenance</summary><pre>{JSON.stringify({ parameters: cap.parameters, capabilities: cap.capabilities, manifest_sha256: cap.manifest_sha256, reason: cap.execution_block_reason }, null, 2)}</pre></details></article>)}</div>}
    </section>}

    <div className="tif-footer"><span>Registry data is persisted in PostgreSQL.</span><span>Last refreshed: {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Not yet'}</span><span>API: {API}</span></div>
  </div>
}

function App() {
  const [section, setSection] = useState<'scope' | 'integrations' | 'assessment' | 'advanced'>('assessment')
  if (section === 'scope') return <ScopeApp onIntegrations={() => setSection('integrations')} onAssessment={() => setSection('assessment')} />
  if (section === 'assessment') return <AssessmentWorkspace onScope={() => setSection('scope')} onIntegrations={() => setSection('integrations')} onAdvanced={() => setSection('advanced')} />
  if (section === 'advanced') return <AdvancedFeatures onScope={() => setSection('scope')} onAssessment={() => setSection('assessment')} />
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><div><strong>SENTINEL</strong><span>ASSESSMENT PLATFORM</span></div></div>
      <div className="side-label">WORKSPACE</div>
      <button className="nav-item" onClick={() => setSection('scope')}><span>▦</span> Projects & scope</button>
      <button className="nav-item" onClick={() => setSection('integrations')}><span>⌘</span> Tool integrations</button>
      <button className="nav-item" onClick={() => setSection('assessment')}><span>◈</span> Assessment operations</button><button className="nav-item" onClick={() => setSection('advanced')}><span>✦</span> Intelligence & delivery</button>
      <div className="side-footer"><span className="status-dot"/> SENTINEL API <small>Human control plane · v0.5.0</small></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><span className="eyebrow">EXTENSIBILITY / REGISTRY</span><h1>Tool integration console</h1></div><div className="top-right"><span className="secure-pill">⌑ Deterministic policy</span><span className="avatar">OP</span></div></header>
      <IntegrationConsole />
    </main>
  </div>
}
export default App
