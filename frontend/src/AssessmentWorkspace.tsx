import { useCallback, useEffect, useState } from 'react'

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
type Project = { id: string; name: string }
type Transcript = { id: string; project_id: string; name: string; status: string }
type Scope = { active: { id: string; version: number; status: string; document?: any } | null; latest?: any }
type Approval = { decision: string; reviewed_by: string; comment?: string | null; created_at: string } | null
type Proposal = { id: string; proposal_group_id: string; version: number; project_id: string; transcript_id: string; origin: string; created_by: string; tool: string; action: string; target: string; parameters: Record<string, unknown>; reason: string; priority: string; status: string; created_at: string; approval: Approval }
type Event = { id: string; sequence_number: number; event_type: string; actor_type: string; actor_id?: string; content: Record<string, any>; created_at: string }

function readableError(error: any): { title: string; message: string; issues: { path: string; message: string }[]; raw: string } {
  const data = error?.data
  const detail = data?.detail
  const issues = Array.isArray(detail) ? detail.map((e: any) => ({ path: (e.loc || []).filter((x: any) => x !== 'body').join('.') || 'request', message: e.msg || 'Invalid value' }))
    : Array.isArray(detail?.errors) ? detail.errors.map((e: any) => ({ path: (e.location || e.loc || []).join('.') || 'request', message: e.message || e.msg || 'Invalid value' })) : []
  return { title: `Request failed${error?.status ? ` · HTTP ${error.status}` : ''}`, message: typeof detail === 'string' ? detail : detail?.message || error?.message || 'Unexpected error', issues, raw: JSON.stringify(data || { message: error?.message }, null, 2) }
}
async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try { response = await fetch(`${API}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) } }) }
  catch { throw Object.assign(new Error(`Cannot reach SENTINEL API at ${API}. Check that the backend container is running and the API URL is correct.`), { status: 0, data: { message: 'Network request failed' } }) }
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw Object.assign(new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || `HTTP ${response.status}`), { status: response.status, data })
  return data as T
}
const post = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
const stamp = (value: string) => { try { return new Date(value).toLocaleString() } catch { return value } }

export default function AssessmentWorkspace({ onScope, onIntegrations, onAdvanced }: { onScope: () => void; onIntegrations: () => void; onAdvanced: () => void }) {
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState('')
  const [transcripts, setTranscripts] = useState<Transcript[]>([])
  const [transcriptId, setTranscriptId] = useState('')
  const [scope, setScope] = useState<Scope | null>(null)
  const [proposals, setProposals] = useState<Proposal[]>([])
  const [events, setEvents] = useState<Event[]>([])
  const [selected, setSelected] = useState<Proposal | null>(null)
  const [tab, setTab] = useState<'queue' | 'history'>('queue')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<any>(null)
  const [notice, setNotice] = useState('')
  const [reviewer, setReviewer] = useState('operator')
  const [comment, setComment] = useState('')
  const [transcriptName, setTranscriptName] = useState('Primary assessment')
  const [showNewTranscript, setShowNewTranscript] = useState(false)
  const [target, setTarget] = useState('')
  const [ports, setPorts] = useState('21,22,80,443,8009,8180')
  const [excludedPorts, setExcludedPorts] = useState('')
  const [edit, setEdit] = useState(false)
  const [draft, setDraft] = useState({ tool: 'nmap', action: 'service_discovery', target: '', parameters: '{\n  "ports": [21, 22, 80, 443]\n}', reason: '', priority: 'medium' })
  const [rawResult, setRawResult] = useState<any>(null)
  const [assistantText, setAssistantText] = useState('')
  const [assistantReply, setAssistantReply] = useState<any>(null)
  const [assistantBusy, setAssistantBusy] = useState(false)
  const [lastExecution, setLastExecution] = useState<any>(null)
  const [vulnerabilityContext, setVulnerabilityContext] = useState<any>(null)
  const [enrichmentBusy, setEnrichmentBusy] = useState(false)
  const [autoPorts, setAutoPorts] = useState('21,22,80,443,8009,8180')
  const [autoSession, setAutoSession] = useState<any>(null)
  const [autoBusy, setAutoBusy] = useState(false)

  const loadProjects = useCallback(async () => { const rows = await api<Project[]>('/projects'); setProjects(rows); if (!projectId && rows.length) setProjectId(rows[0].id) }, [projectId])
  const loadProjectData = useCallback(async (id: string) => {
    if (!id) return
    const [scopeData, transcriptRows] = await Promise.all([api<Scope>(`/projects/${id}/scope`), api<Transcript[]>(`/projects/${id}/transcripts`)]);
    setScope(scopeData); setTranscripts(transcriptRows)
    if (transcriptId && transcriptRows.some(t => t.id === transcriptId)) return
    setTranscriptId(transcriptRows[0]?.id || '')
  }, [transcriptId])
  const refreshActivity = useCallback(async () => {
    if (!projectId) return
    const query = transcriptId ? `?transcript_id=${encodeURIComponent(transcriptId)}` : ''
    const [proposalData, eventData] = await Promise.all([
      api<{ proposals: Proposal[] }>(`/projects/${projectId}/proposals${query}`),
      transcriptId ? api<Event[]>(`/transcripts/${transcriptId}/events`) : Promise.resolve([] as Event[]),
    ])
    setProposals(proposalData.proposals); setEvents(eventData)
    if (selected) setSelected(proposalData.proposals.find(p => p.id === selected.id) || null)
  }, [projectId, transcriptId, selected])
  useEffect(() => { loadProjects().catch(setError) }, [])
  useEffect(() => { if (projectId) loadProjectData(projectId).catch(setError) }, [projectId])
  useEffect(() => { if (projectId && transcriptId) refreshActivity().catch(setError); else { setProposals([]); setEvents([]) } }, [projectId, transcriptId])

  useEffect(() => {
    if (!autoSession?.id || ['COMPLETED', 'FAILED', 'STOPPED'].includes(autoSession.status)) return
    const timer = window.setInterval(() => {
      api<any>(`/autonomous/${autoSession.id}`).then(setAutoSession).catch(setError)
    }, 1200)
    return () => window.clearInterval(timer)
  }, [autoSession?.id, autoSession?.status])

  const runBusy = async (fn: () => Promise<any>, success: string) => { setBusy(true); setError(null); setNotice(''); setRawResult(null); try { const result = await fn(); setRawResult(result); setNotice(success); await refreshActivity(); return result } catch (e) { setError(e); return null } finally { setBusy(false) } }
  const createTranscript = async () => {
    if (!transcriptName.trim() || !projectId) return
    const row = await runBusy(() => api<Transcript>(`/projects/${projectId}/transcripts`, post({ name: transcriptName.trim() })), 'Assessment transcript created.')
    if (row) { const rows = await api<Transcript[]>(`/projects/${projectId}/transcripts`); setTranscripts(rows); setTranscriptId(row.id); setShowNewTranscript(false) }
  }
  const startAssessment = async () => {
    if (!scope?.active) { setError(new Error('No active scope. Configure and activate a scope before creating assessment proposals.')); return }
    const parsedPorts = ports.split(',').map(v => Number(v.trim())).filter(Number.isInteger)
    const parsedExcluded = excludedPorts.trim() ? excludedPorts.split(',').map(v => Number(v.trim())).filter(Number.isInteger) : []
    if (!target.trim() || !parsedPorts.length || parsedPorts.some(p => p < 1 || p > 65535)) { setError(new Error('Enter a target and one or more valid ports (1–65535).')); return }
    await runBusy(() => api('/assessment/run', post({ project_id: projectId, transcript_id: transcriptId, target: target.trim(), requested_by: reviewer, ports: parsedPorts, excluded_ports: parsedExcluded })), 'Initial discovery proposal created. It has NOT been executed; review and approve it below.')
  }
  const createManualProposal = async () => {
    let parameters: any
    try { parameters = JSON.parse(draft.parameters) } catch { setError(new Error('Parameters must be valid JSON.')); return }
    await runBusy(() => api(`/projects/${projectId}/transcripts/${transcriptId}/proposals`, post({ origin: 'HUMAN', created_by: reviewer, tool: draft.tool, action: draft.action, target: draft.target, parameters, reason: draft.reason, priority: draft.priority })), 'Proposal created and added to the review queue.')
    setEdit(false)
  }
  const openEdit = (p: Proposal) => { setSelected(p); setDraft({ tool: p.tool, action: p.action, target: p.target, parameters: JSON.stringify(p.parameters, null, 2), reason: p.reason, priority: p.priority }); setEdit(true) }
  const saveRevision = async () => {
    if (!selected) return
    let parameters: any
    try { parameters = JSON.parse(draft.parameters) } catch { setError(new Error('Parameters must be valid JSON.')); return }
    await runBusy(() => api(`/proposals/${selected.id}/revise`, post({ edited_by: reviewer, tool: draft.tool, action: draft.action, target: draft.target, parameters, reason: draft.reason, priority: draft.priority })), 'New proposal version created. The previous version is superseded and must be reviewed again.')
    setEdit(false)
  }
  const decide = async (decision: 'APPROVED' | 'REJECTED') => {
    if (!selected) return
    if (decision === 'APPROVED' && !window.confirm(`Approve ${selected.tool}.${selected.action} against ${selected.target}? Execution will still require a separate click and server-side scope authorization.`)) return
    await runBusy(() => api(`/proposals/${selected.id}/decision`, post({ reviewed_by: reviewer, decision, comment: comment || null })), `Proposal ${decision.toLowerCase()}.`)
    setComment('')
  }
  const askAI = async (message?: string, errorContext?: any, executionResult?: any) => {
    if (!projectId || !transcriptId || !target.trim()) return
    setAssistantBusy(true); setError(null); setAssistantReply(null)
    try {
      const response = await api<any>('/assessment/assist', post({
        project_id: projectId, transcript_id: transcriptId,
        target: selected?.target || target.trim(),
        user_message: message || (errorContext ? 'Fix this execution error. Diagnose the scanner contract mismatch and propose a corrected action.' : 'Analyse the latest assessment results and recommend the next safe investigation steps.'),
        execution_result: executionResult || lastExecution,
        error_context: errorContext || null,
        vulnerability_context: vulnerabilityContext,
      }))
      setAssistantReply(response); setNotice(`AI analysis complete. ${response.proposal_count || 0} proposal(s) added to the approval queue.`)
      await refreshActivity()
    } catch (e) { setError(e) } finally { setAssistantBusy(false) }
  }

  const enrichLatestExecution = async () => {
    const xml = lastExecution?.scanner_result?.result?.stdout
      || lastExecution?.scanner_result?.stdout
      || lastExecution?.result?.stdout
    if (!xml || !String(xml).includes('<nmaprun')) {
      setError(new Error('The latest execution does not contain Nmap XML stdout. Select an Nmap execution with XML output first.'))
      return
    }
    setEnrichmentBusy(true); setError(null); setNotice('')
    try {
      const result = await api<any>('/assessment/enrich', post({ nmap_xml: xml }))
      setVulnerabilityContext(result)
      setNotice(`Optional enrichment complete: ${result.service_count} services, ${result.candidate_count} CVE candidates. It has not been sent to AI yet.`)
    } catch (e) { setError(e) } finally { setEnrichmentBusy(false) }
  }


  const startAutonomous = async () => {
    if (!scope?.active) { setError(new Error('Autonomous mode requires an active approved scope.')); return }
    if (!projectId || !transcriptId || !target.trim()) { setError(new Error('Select a project and transcript, and enter an in-scope target.')); return }
    const approvedPorts = autoPorts.split(',').map(v => Number(v.trim())).filter(Number.isInteger)
    if (!approvedPorts.length || approvedPorts.some(p => p < 1 || p > 65535)) { setError(new Error('Enter valid TCP ports between 1 and 65535.')); return }
    setAutoBusy(true); setError(null); setNotice('')
    try {
      const started = await api<any>('/autonomous/start', post({
        project_id: projectId, transcript_id: transcriptId, target: target.trim(),
        started_by: reviewer, ports: approvedPorts
      }))
      const fresh = await api<any>(`/autonomous/${started.id}`)
      setAutoSession(fresh)
      setNotice('Autonomous scan-only session started. Live system logs are displayed below.')
    } catch (e) { setError(e) } finally { setAutoBusy(false) }
  }
  const stopAutonomous = async () => {
    if (!autoSession?.id) return
    setAutoBusy(true); setError(null)
    try {
      await api<any>(`/autonomous/${autoSession.id}/stop`, post({}))
      const fresh = await api<any>(`/autonomous/${autoSession.id}`)
      setAutoSession(fresh)
      setNotice('Stop requested. The current scanner operation may finish; no subsequent scans will be started.')
    } catch (e) { setError(e) } finally { setAutoBusy(false) }
  }
  const refreshAutonomous = async () => {
    if (!autoSession?.id) return
    try { setAutoSession(await api<any>(`/autonomous/${autoSession.id}`)) }
    catch (e) { setError(e) }
  }

  const execute = async () => {
    if (!selected || selected.status !== 'APPROVED') return
    if (!window.confirm('Execute this approved proposal? The backend will re-check active scope, limits and authorization before dispatch.')) return
    setBusy(true); setError(null); setNotice('')
    try {
      const result = await api<any>(`/proposals/${selected.id}/execute`, post({}))
      setRawResult(result); setLastExecution(result); setNotice('Execution request finished. You can now ask AI to analyse the result.'); await refreshActivity()
    } catch (e: any) {
      setError(e)
      const context = { proposal: { id: selected.id, tool: selected.tool, action: selected.action, target: selected.target, parameters: selected.parameters, reason: selected.reason }, failure: { status: e?.status || null, message: e?.message || 'Execution failed', response: e?.data || null } }
      // Automatically send the execution error to AI for a repair suggestion.
      await askAI('Fix this execution error. Explain the exact parameter contract and create a corrected proposal for human review.', context, null)
    } finally { setBusy(false) }
  }

  const pending = proposals.filter(p => p.status === 'PROPOSED')
  const approved = proposals.filter(p => p.status === 'APPROVED')
  const completed = proposals.filter(p => ['COMPLETED', 'FAILED', 'REJECTED', 'SUPERSEDED'].includes(p.status))
  const form = (revision = false) => <div className="ops-form">
    <div className="ops-form-grid"><label>Tool<input value={draft.tool} onChange={e => setDraft({ ...draft, tool: e.target.value })} /></label><label>Operation<input value={draft.action} onChange={e => setDraft({ ...draft, action: e.target.value })} /></label><label className="wide">Target<input value={draft.target} onChange={e => setDraft({ ...draft, target: e.target.value })} /></label><label>Priority<select value={draft.priority} onChange={e => setDraft({ ...draft, priority: e.target.value })}>{['critical','high','medium','low'].map(v => <option key={v}>{v}</option>)}</select></label><label className="wide">Reason<textarea value={draft.reason} onChange={e => setDraft({ ...draft, reason: e.target.value })} rows={2}/></label><label className="wide">Parameters · JSON<textarea className="ops-code" value={draft.parameters} onChange={e => setDraft({ ...draft, parameters: e.target.value })} rows={7} spellCheck={false}/></label></div>
    <div className="ops-actions"><button className="ops-btn ghost" onClick={() => setEdit(false)}>Cancel</button><button className="ops-btn primary" disabled={busy || !draft.tool.trim() || !draft.action.trim() || !draft.target.trim() || !draft.reason.trim()} onClick={revision ? saveRevision : createManualProposal}>{revision ? 'Save new version' : 'Create proposal'}</button></div>
  </div>

  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark">S</div><div><strong>SENTINEL</strong><span>ASSESSMENT PLATFORM</span></div></div><div className="side-label">WORKSPACE</div><button className="nav-item" onClick={onScope}><span>▦</span> Projects & scope</button><button className="nav-item" onClick={onIntegrations}><span>⌘</span> Tool integrations</button><button className="nav-item active"><span>◈</span> Assessment operations</button><button className="nav-item" onClick={onAdvanced}><span>✦</span> Intelligence & delivery</button><div className="side-footer"><span className="status-dot"/> HUMAN CONTROL PLANE<small>Proposal · Approval · GATE</small></div></aside>
    <main className="main-content"><header className="topbar"><div><span className="eyebrow">ASSESSMENT / HUMAN CONTROL</span><h1>Assessment operations</h1></div><div className="top-right"><span className="secure-pill">⌑ Scope enforced server-side</span><span className="avatar">OP</span></div></header>
      <div className="ops-page"><div className="ops-intro"><div><span className="tif-eyebrow">CONTROLLED TESTING WORKSPACE</span><h2>Review every action before it runs.</h2><p>Proposals are versioned. Approval is separate from execution. The backend re-checks scope at dispatch.</p></div><div className={`ops-scope ${scope?.active ? 'good' : 'bad'}`}><i /><div><strong>{scope?.active ? `SCOPE v${scope.active.version} ACTIVE` : 'NO ACTIVE SCOPE'}</strong><small>{scope?.active ? 'Execution can be requested after approval' : 'Execution is blocked until scope activation'}</small></div></div></div>
      {error && <ErrorPanel error={error} onClose={() => setError(null)}/>}{notice && <div className="ops-notice"><span>✓</span><div>{notice}{rawResult && <details><summary>Inspect API response</summary><pre>{JSON.stringify(rawResult, null, 2)}</pre></details>}</div><button onClick={() => setNotice('')}>×</button></div>}
      <div className="ops-context"><label>Project<select value={projectId} onChange={e => { setProjectId(e.target.value); setTranscriptId(''); setSelected(null) }}><option value="">Select project</option>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label><label>Transcript<select value={transcriptId} onChange={e => { setTranscriptId(e.target.value); setSelected(null) }}><option value="">Select transcript</option>{transcripts.map(t => <option key={t.id} value={t.id}>{t.name} · {t.status}</option>)}</select></label><button className="ops-btn ghost" disabled={!projectId} onClick={() => setShowNewTranscript(v => !v)}>＋ New transcript</button><button className="ops-btn ghost" disabled={!projectId || !transcriptId} onClick={() => { refreshActivity().catch(setError); loadProjectData(projectId).catch(setError) }}>↻ Refresh</button></div>
      {showNewTranscript && <div className="ops-create-transcript"><input value={transcriptName} onChange={e => setTranscriptName(e.target.value)} placeholder="Transcript name"/><button className="ops-btn primary" disabled={busy || !transcriptName.trim()} onClick={createTranscript}>Create transcript</button></div>}
      {!projectId ? <div className="ops-empty"><strong>Select a project to begin</strong><p>Projects are created in Projects & Scope.</p><button className="ops-btn ghost" onClick={onScope}>Open Projects & Scope</button></div> : !scope?.active ? <div className="ops-blocked"><strong>Assessment execution is unavailable</strong><p>This project has no active scope. Create and activate an authorized scope before submitting proposals for execution.</p><button className="ops-btn ghost" onClick={onScope}>Configure scope →</button></div> : !transcriptId ? <div className="ops-empty"><strong>Create an assessment transcript</strong><p>A transcript groups proposals, approvals, execution events and assessment history.</p><button className="ops-btn primary" onClick={() => setShowNewTranscript(true)}>＋ Create transcript</button></div> : <>
      <div className="ops-stats"><div><span>AWAITING REVIEW</span><strong>{pending.length}</strong><small>Human decision required</small></div><div><span>APPROVED</span><strong>{approved.length}</strong><small>Not yet executed</small></div><div><span>TERMINAL STATES</span><strong>{completed.length}</strong><small>Completed / failed / rejected</small></div><div><span>TRANSCRIPT EVENTS</span><strong>{events.length}</strong><small>Append-only activity</small></div></div>
      <section className="ops-panel ops-ai-assistant"><div className="ops-panel-head"><div><span className="tif-kicker">AI PROVIDER / INVESTIGATION COPILOT</span><h3>Talk to the assessment planner</h3><p>Ask questions about evidence, or request a repair. AI can suggest proposals but cannot execute them.</p></div><span className="ops-count">HUMAN APPROVAL REQUIRED</span></div><div className="ops-ai-compose"><textarea value={assistantText} onChange={e => setAssistantText(e.target.value)} rows={2} placeholder="e.g. Why did the HTTP probe fail? Fix the parameters and suggest a corrected request…"/><button className="ops-btn primary" disabled={assistantBusy || busy || !assistantText.trim()} onClick={() => { const msg = assistantText; setAssistantText(''); askAI(msg) }}>{assistantBusy ? 'Asking AI…' : '✦ Ask AI'}</button><button className="ops-btn ghost" disabled={assistantBusy || busy || !lastExecution} onClick={() => askAI('Analyse this execution result and propose the next safe investigation steps.', null, lastExecution)}>Analyse latest result</button><button className="ops-btn ghost" disabled={enrichmentBusy || !lastExecution} onClick={enrichLatestExecution}>{enrichmentBusy ? 'Enriching…' : 'Run optional CPE/CVE enrichment'}</button><button className="ops-btn ghost" disabled={!vulnerabilityContext || assistantBusy || busy} onClick={() => askAI('Analyse the latest scan together with the optional CVE enrichment and recommend safe next steps.', null, lastExecution)}>Send enriched evidence to AI</button></div>{vulnerabilityContext && <div className="ops-ai-success">Optional enrichment is ready ({vulnerabilityContext.candidate_count} CVE candidates). It will only be sent when you explicitly click “Send enriched evidence to AI”.</div>}{assistantReply && <div className="ops-ai-reply"><strong>AI · {assistantReply.model || 'provider'}</strong><p>{assistantReply.assistant_message}</p>{(assistantReply.observations || []).map((o: any, i: number) => <div key={i} className="ops-ai-observation">{typeof o === 'string' ? o : JSON.stringify(o)}</div>)}{assistantReply.proposal_count > 0 && <div className="ops-ai-success">{assistantReply.proposal_count} proposal(s) created. Review them in the approval queue below.</div>}<details><summary>Provider diagnostics</summary><pre>{JSON.stringify(assistantReply.diagnostics || {}, null, 2)}</pre></details></div>}</section>
      <section className="ops-panel ops-autonomous">
        <div className="ops-panel-head"><div><span className="tif-kicker">SUPERVISED AUTONOMOUS SCANNING</span><h3>Autonomous assessment mode</h3><p>Start from this Assessment Operations workspace. AI receives the scan observations and may propose bounded Nmap service-discovery scans. Every operation is re-authorized by GATE.</p></div><span className={`ops-count ${autoSession && !['COMPLETED','FAILED','STOPPED'].includes(autoSession.status) ? 'running' : ''}`}>{autoSession?.status || 'IDLE'}</span></div>
        {!autoSession ? <div className="ops-autonomous-start">
          <label>Approved TCP ports<input value={autoPorts} onChange={e => setAutoPorts(e.target.value)} placeholder="21,22,80,443,8009,8180"/></label>
          <button className="ops-btn primary" disabled={autoBusy || busy || !scope?.active || !projectId || !transcriptId || !target.trim()} onClick={startAutonomous}>▶ Start autonomous scan-only mode</button>
          {!scope?.active && <small>Activate an approved scope before starting autonomous scanning.</small>}
        </div> : <div className="ops-autonomous-live">
          <div className="ops-autonomous-meta"><div><small>SESSION ID</small><strong>{autoSession.id}</strong></div><div><small>TARGET</small><strong>{autoSession.target}</strong></div><div><small>SESSION STATE</small><strong>{autoSession.status}</strong></div>{['COMPLETED','FAILED','STOPPED'].includes(autoSession.status) ? <button className="ops-btn primary" disabled={autoBusy || !scope?.active} onClick={startAutonomous}>↻ Start another session</button> : <button className="ops-btn danger" disabled={autoBusy || autoSession.stop_requested} onClick={stopAutonomous}>■ Stop mode</button>}</div>
          <div className="ops-autonomous-log-head"><strong>Live system log</strong><button className="ops-btn ghost" onClick={refreshAutonomous}>↻ Refresh logs</button><span>{(autoSession.events || []).length} events</span></div>
          <div className="ops-autonomous-logs" aria-live="polite">
            {(autoSession.events || []).map((event: any) => <article className={`ops-auto-log ${String(event.type).includes('failed') || event.type === 'error' ? 'failed' : event.type === 'blocked' ? 'blocked' : ''}`} key={event.id}>
              <time>{stamp(event.at)}</time><strong>{String(event.type || 'event').replaceAll('_',' ').toUpperCase()}</strong><span>{event.message}</span>
              {event.data && Object.keys(event.data).length > 0 && <details><summary>Details</summary><pre>{JSON.stringify(event.data,null,2)}</pre></details>}
            </article>)}
            {!(autoSession.events || []).length && <div className="ops-empty compact">Waiting for the first session event…</div>}
          </div>
          <div className="ops-autonomous-policy">Autonomous v1 is scan-only: Nmap TCP service discovery. Code injection, exploit attempts, authentication attacks and state-changing operations are rejected. Stop prevents subsequent scans; an in-flight scanner call may finish.</div>
        </div>}
      </section>
      <div className="ops-launch"><div><span className="tif-kicker">INITIAL DISCOVERY</span><h3>Request an Nmap service discovery</h3><p>Creates a proposal only. It does not start a scan.</p></div><div className="ops-launch-fields"><label>Target<input value={target} onChange={e => setTarget(e.target.value)} placeholder="192.168.56.101"/></label><label>Ports<input value={ports} onChange={e => setPorts(e.target.value)} placeholder="22,80,443"/></label><label>Exclude ports<input value={excludedPorts} onChange={e => setExcludedPorts(e.target.value)} placeholder="Optional"/></label><button className="ops-btn primary" disabled={busy || !target.trim()} onClick={startAssessment}>Create discovery proposal</button></div></div>
      <div className="ops-toolbar"><div className="ops-tabs"><button className={tab === 'queue' ? 'active' : ''} onClick={() => setTab('queue')}>Approval queue <b>{pending.length}</b></button><button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>All proposals <b>{proposals.length}</b></button></div><button className="ops-btn ghost" onClick={() => { setDraft({ tool: 'nmap', action: 'service_discovery', target: target || '', parameters: '{\n  "ports": [22, 80, 443]\n}', reason: '', priority: 'medium' }); setSelected(null); setEdit(true) }}>＋ Manual proposal</button></div>
      {edit && <section className="ops-panel"><div className="ops-panel-head"><div><span className="tif-kicker">{selected ? `REVISING VERSION ${selected.version}` : 'HUMAN-GENERATED ACTION'}</span><h3>{selected ? 'Edit proposal' : 'Create proposal'}</h3><p>{selected ? 'A revision supersedes the previous version and requires a fresh approval.' : 'Use a registered operation identifier. The server remains the authority on whether it is executable.'}</p></div></div>{form(Boolean(selected))}</section>}
      <div className="ops-columns"><section className="ops-panel"><div className="ops-panel-head"><div><span className="tif-kicker">{tab === 'queue' ? 'HUMAN DECISIONS' : 'PROPOSAL LEDGER'}</span><h3>{tab === 'queue' ? 'Action approval queue' : 'Proposal history'}</h3><p>{tab === 'queue' ? 'Inspect, edit, approve or reject proposed operations.' : 'All versions and terminal states for this transcript.'}</p></div><span className="ops-count">{tab === 'queue' ? pending.length : proposals.length} ITEMS</span></div>
        {(tab === 'queue' ? pending : proposals).length === 0 ? <div className="ops-empty compact"><strong>{tab === 'queue' ? 'Nothing awaiting approval' : 'No proposals yet'}</strong><p>Create an initial discovery proposal or add a manual proposal to begin.</p></div> : <div className="ops-proposal-list">{(tab === 'queue' ? pending : proposals).map(p => <button key={p.id} className={`ops-proposal ${selected?.id === p.id ? 'selected' : ''}`} onClick={() => { setSelected(p); setComment(''); setEdit(false) }}><div className="ops-proposal-top"><span className={`ops-priority ${p.priority}`}>{p.priority}</span><span className={`ops-status ${p.status.toLowerCase()}`}>{p.status}</span></div><strong>{p.tool}<i>.</i>{p.action}</strong><span className="ops-target">{p.target}</span><small>v{p.version} · {p.origin} · {stamp(p.created_at)}</small></button>)}</div>}
      </section>
      <section className="ops-panel ops-inspector"><div className="ops-panel-head"><div><span className="tif-kicker">PROPOSAL INSPECTOR</span><h3>{selected ? `Version ${selected.version}` : 'Select an action'}</h3><p>{selected ? selected.id : 'Choose a proposal from the queue to inspect its details and take action.'}</p></div></div>
        {!selected ? <div className="ops-empty compact"><strong>No proposal selected</strong><p>Proposal parameters, approval history and execution controls will appear here.</p></div> : <><div className="ops-detail-grid"><div><small>TOOL / ACTION</small><strong>{selected.tool}.{selected.action}</strong></div><div><small>STATUS</small><strong>{selected.status}</strong></div><div><small>TARGET</small><strong>{selected.target}</strong></div><div><small>CREATED BY</small><strong>{selected.created_by}</strong></div></div><div className="ops-detail-block"><small>REASON</small><p>{selected.reason}</p></div><div className="ops-detail-block"><small>PARAMETERS</small><pre>{JSON.stringify(selected.parameters, null, 2)}</pre></div>{selected.approval && <div className="ops-approval-record"><strong>{selected.approval.decision} by {selected.approval.reviewed_by}</strong><p>{selected.approval.comment || 'No reviewer comment.'}</p><small>{stamp(selected.approval.created_at)}</small></div>}
          <label className="ops-reviewer">Reviewer / operator<input value={reviewer} onChange={e => setReviewer(e.target.value)} placeholder="Your reviewer label"/></label>
          {selected.status === 'PROPOSED' && <><label className="ops-reviewer">Review comment<textarea value={comment} onChange={e => setComment(e.target.value)} rows={2} placeholder="Why approve or reject?"/></label><div className="ops-actions wrap"><button className="ops-btn ghost" onClick={() => openEdit(selected)}>Edit proposal</button><button className="ops-btn danger" disabled={busy || !reviewer.trim()} onClick={() => decide('REJECTED')}>Reject</button><button className="ops-btn primary" disabled={busy || !reviewer.trim()} onClick={() => decide('APPROVED')}>Approve version</button></div></>}
          {selected.status === 'APPROVED' && <div className="ops-execute"><p>Approved version. Execution is a separate action and will trigger fresh server-side scope and limit checks.</p><button className="ops-btn primary" disabled={busy} onClick={execute}>▶ Execute approved action</button></div>}
          {['COMPLETED','FAILED','REJECTED','SUPERSEDED'].includes(selected.status) && <div className="ops-terminal">This proposal is in a terminal state. To change its parameters, create a new proposal rather than altering this record.</div>}
        </>}
      </section></div>
      <section className="ops-panel ops-timeline"><div className="ops-panel-head"><div><span className="tif-kicker">AUDIT TRAIL</span><h3>Assessment timeline</h3><p>Events recorded against the selected transcript.</p></div><span className="ops-count">{events.length} EVENTS</span></div>{events.length === 0 ? <div className="ops-empty compact"><strong>No events recorded</strong><p>Proposal and execution activity will appear here.</p></div> : <div className="ops-event-list">{[...events].reverse().map(e => <article key={e.id}><i/><div><strong>{e.event_type.replaceAll('.', ' ')}</strong><p>{e.actor_type}{e.actor_id ? ` · ${e.actor_id}` : ''}</p><small>{stamp(e.created_at)} · #{e.sequence_number}</small><details><summary>Event payload</summary><pre>{JSON.stringify(e.content, null, 2)}</pre></details></div></article>)}</div>}</section>
      </>}
      <footer>S E N T I N E L <span>·</span> Approval and execution authority remains server-side.</footer></div>
    </main></div>
}

function ErrorPanel({ error, onClose }: { error: any; onClose: () => void }) {
  const parsed = readableError(error)
  return <div className="ops-error"><div className="ops-error-head"><strong>⚠ {parsed.title}</strong><button onClick={onClose}>×</button></div><p>{parsed.message}</p>{parsed.issues.length > 0 && <div className="ops-error-issues"><strong>Validation details</strong>{parsed.issues.map((i, n) => <div key={n}><code>{i.path}</code><span>{i.message}</span></div>)}</div>}<details><summary>Raw API response · useful for debugging</summary><pre>{parsed.raw}</pre></details></div>
}
