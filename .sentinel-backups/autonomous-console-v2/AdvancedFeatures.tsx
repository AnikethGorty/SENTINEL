import { useEffect, useMemo, useState } from 'react'

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
async function api(path: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) } })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || JSON.stringify(data.detail || data))
  return data
}
const post = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
type Project = { id: string; name: string }
type Transcript = { id: string; name: string }
type Component = { id: string; kind: string; title: string; content: string; status: string; evidence?: any[]; cve?: any; severity?: string }
type Report = { id: string; title: string; status: string; components: Component[]; approved_by?: string }

export default function AdvancedFeatures({ onAssessment, onScope }: { onAssessment: () => void; onScope: () => void }) {
  const [tab, setTab] = useState<'cpe'|'reports'|'autonomous'>('cpe')
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState('')
  const [transcripts, setTranscripts] = useState<Transcript[]>([])
  const [transcriptId, setTranscriptId] = useState('')
  const [target, setTarget] = useState('')
  const [reviewer, setReviewer] = useState('operator')
  const [xml, setXml] = useState('')
  const [servicesJson, setServicesJson] = useState('')
  const [cpeCriteria, setCpeCriteria] = useState('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
  const [cpeObserved, setCpeObserved] = useState('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
  const [cpeComparison, setCpeComparison] = useState<any>(null)
  const [enriched, setEnriched] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [report, setReport] = useState<Report|null>(null)
  const [editing, setEditing] = useState<string|null>(null)
  const [editText, setEditText] = useState('')
  const [autoPorts, setAutoPorts] = useState('21,22,80,443,8009,8180')
  const [autoSession, setAutoSession] = useState<any>(null)

  useEffect(() => { api('/projects').then((rows: Project[]) => { setProjects(rows); if (rows[0]) setProjectId(rows[0].id) }).catch(e => setError(e.message)) }, [])
  useEffect(() => { if (!projectId) return; api(`/projects/${projectId}/transcripts`).then((rows: Transcript[]) => { setTranscripts(rows); setTranscriptId(rows[0]?.id || '') }).catch(e => setError(e.message)) }, [projectId])
  useEffect(() => {
    if (!autoSession?.id || ['COMPLETED','FAILED','STOPPED'].includes(autoSession.status)) return
    const timer = window.setInterval(() => api(`/autonomous/${autoSession.id}`).then(setAutoSession).catch(e => setError(e.message)), 1800)
    return () => window.clearInterval(timer)
  }, [autoSession?.id, autoSession?.status])

  const run = async (fn: () => Promise<any>, msg: string) => {
    setBusy(true); setError(''); setNotice('')
    try { const value = await fn(); setNotice(msg); return value }
    catch (e: any) { setError(e.message || 'Request failed'); return null }
    finally { setBusy(false) }
  }
  const enrich = async () => {
    let body: any
    try { body = xml.trim() ? { nmap_xml: xml } : { services: JSON.parse(servicesJson || '[]') } }
    catch { setError('Service observations must be valid JSON.'); return }
    const result = await run(() => api('/assessment/enrich', post(body)), 'CPE/CVE enrichment completed manually.')
    if (result) setEnriched(result)
  }
  const compareCpe = async () => {
    const result = await run(() => api('/assessment/cpe/compare', post({ criteria: cpeCriteria, observed: cpeObserved })), 'CPE comparison completed manually.')
    if (result) setCpeComparison(result)
  }
  const sendToGemini = async () => {
    if (!enriched || !projectId || !transcriptId || !target.trim()) { setError('Select a project/transcript and enter the authorized target first.'); return }
    const result = await run(() => api('/assessment/assist', post({
      project_id: projectId, transcript_id: transcriptId, target,
      user_message: 'Analyse the scan evidence together with this manually requested vulnerability enrichment. Treat CVE candidates as unverified intelligence, identify evidence gaps, and propose only safe next investigations.',
      vulnerability_context: enriched
    })), 'Enriched context sent to Gemini. Any proposed actions remain subject to human approval.')
    if (result) setNotice(`${result.assistant_message || 'Gemini analysis complete'} · ${result.proposal_count || 0} proposal(s) created for review.`)
  }
  const createReport = async () => {
    if (!enriched || !projectId || !transcriptId) { setError('Run enrichment and select a project/transcript first.'); return }
    const result = await run(() => api('/reports/drafts', post({
      project_id: projectId, transcript_id: transcriptId, target: target || 'Not specified',
      title: 'SENTINEL VDP-Style Security Assessment Report',
      scope_summary: 'Approved scope recorded in SENTINEL project configuration.',
      services: enriched.services,
      executive_summary: `SENTINEL observed ${enriched.service_count} service(s) and generated ${enriched.candidate_count} curated CVE candidate(s). These candidates require human review and verification; they are not assertions of successful exploitation.`,
      limitations: enriched.limitations || []
    })), 'Draft created. Every component is pending human review.')
    if (result) { setReport(result); setTab('reports') }
  }
  const decideComponent = async (c: Component, decision: string) => {
    const content = decision === 'EDITED' ? editText : undefined
    const result = await run(() => api(`/reports/${report!.id}/components/${c.id}/decision`, post({ decision, edited_content: content, reviewed_by: reviewer })), `Component marked ${decision.toLowerCase()}.`)
    if (result) { setReport(result); setEditing(null) }
  }
  const approveReport = async () => {
    if (!report) return
    const result = await run(() => api(`/reports/${report.id}/approve`, post({ approved_by: reviewer })), 'Final report approved and locked.')
    if (result) setReport(result)
  }
  const downloadReport = () => { if (report) window.open(`${API}/reports/${report.id}/download`, '_blank') }
  const startAuto = async () => {
    const ports = autoPorts.split(',').map(x => Number(x.trim())).filter(x => Number.isInteger(x) && x >= 1 && x <= 65535)
    if (!ports.length || !target.trim() || !projectId || !transcriptId) { setError('Select a project/transcript, enter an in-scope target and valid ports.'); return }
    const result = await run(() => api('/autonomous/start', post({ project_id: projectId, transcript_id: transcriptId, target, ports, started_by: reviewer })), 'Autonomous scan-only session started.')
    if (result) setAutoSession({ ...result, events: [], results: [] })
  }
  const stopAuto = async () => {
    if (!autoSession?.id) return
    const result = await run(() => api(`/autonomous/${autoSession.id}/stop`, post({})), 'Stop requested. The current scanner call may finish before the session exits.')
    if (result) setAutoSession((old: any) => ({ ...old, ...result }))
  }
  const counts = useMemo(() => ({ accepted: report?.components.filter(c => ['ACCEPTED','EDITED'].includes(c.status)).length || 0, removed: report?.components.filter(c => c.status === 'REMOVED').length || 0, pending: report?.components.filter(c => c.status === 'PENDING').length || 0 }), [report])

  return <div className="app-shell"><aside className="sidebar">
    <div className="brand"><div className="brand-mark">S</div><div><strong>SENTINEL</strong><span>ASSESSMENT PLATFORM</span></div></div>
    <div className="side-label">WORKSPACE</div>
    <button className="nav-item" onClick={onScope}>▦ Projects & scope</button>
    <button className="nav-item" onClick={onAssessment}>◈ Assessment operations</button>
    <button className="nav-item active">✦ Intelligence & delivery</button>
    <div className="side-footer"><span className="status-dot"/> HUMAN CONTROL PLANE<small>Enrichment · Review · Supervision</small></div>
  </aside><main className="main-content">
    <header className="topbar"><div><span className="eyebrow">INTELLIGENCE / DELIVERY</span><h1>Assessment intelligence</h1></div><div className="top-right"><span className="secure-pill">Human approval required</span></div></header>
    <div className="advanced-wrap">
      <div className="advanced-projectbar">
        <label>Project<select value={projectId} onChange={e => setProjectId(e.target.value)}>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        <label>Assessment transcript<select value={transcriptId} onChange={e => setTranscriptId(e.target.value)}>{transcripts.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
        <label>Authorized target<input value={target} onChange={e => setTarget(e.target.value)} placeholder="e.g. 192.168.56.101"/></label>
        <label>Reviewer<input value={reviewer} onChange={e => setReviewer(e.target.value)}/></label>
      </div>
      <div className="advanced-tabs">
        <button className={tab==='cpe'?'selected':''} onClick={()=>setTab('cpe')}>01 · Optional CPE enrichment</button>
        <button className={tab==='reports'?'selected':''} onClick={()=>setTab('reports')}>02 · Report creator</button>
        <button className={tab==='autonomous'?'selected':''} onClick={()=>setTab('autonomous')}>03 · Autonomous mode</button>
      </div>
      {error && <div className="advanced-alert error">{error}</div>}{notice && <div className="advanced-alert success">{notice}</div>}
      {tab==='cpe' && <section className="advanced-panel">
        <div className="advanced-heading"><div><span className="eyebrow">OPTIONAL · OPERATOR INVOKED</span><h2>CPE / CVE enrichment</h2><p>Nothing runs automatically. Paste Nmap XML or service observations, then explicitly invoke the deterministic enrichment engine.</p></div><span className="advanced-badge">OFF BY DEFAULT</span></div>
        <label className="advanced-field">Nmap XML<textarea rows={9} value={xml} onChange={e=>setXml(e.target.value)} placeholder="Paste the stdout XML from an Nmap execution…"/></label>
        <div className="advanced-cpe-compare">
          <h3>Direct CPE matcher</h3>
          <p>Compare an NVD-style CPE 2.3 criterion with an observed CPE whenever you choose.</p>
          <label className="advanced-field">CPE criterion<input value={cpeCriteria} onChange={e=>setCpeCriteria(e.target.value)}/></label>
          <label className="advanced-field">Observed CPE<input value={cpeObserved} onChange={e=>setCpeObserved(e.target.value)}/></label>
          <button className="ops-btn ghost" disabled={busy || !cpeCriteria.trim() || !cpeObserved.trim()} onClick={compareCpe}>Call cpe_matcher</button>
          {cpeComparison && <pre className="advanced-json">{JSON.stringify(cpeComparison,null,2)}</pre>}
        </div>
        <div className="advanced-or">OR</div>
        <label className="advanced-field">Service observations · JSON<textarea rows={5} value={servicesJson} onChange={e=>setServicesJson(e.target.value)} placeholder={'[{"host":"192.168.56.101","port":80,"name":"http","product":"Apache httpd","version":"2.4.49","cpes":[]}]'}/></label>
        <div className="advanced-actions"><button className="ops-btn primary" disabled={busy || (!xml.trim() && !servicesJson.trim())} onClick={enrich}>Run enrichment now</button><button className="ops-btn ghost" disabled={!enriched || busy} onClick={sendToGemini}>Send enriched context to Gemini</button><button className="ops-btn ghost" disabled={!enriched || busy} onClick={createReport}>Create report draft from enrichment</button></div>
        {enriched && <><div className="advanced-stats"><div><strong>{enriched.service_count}</strong><span>Services</span></div><div><strong>{enriched.candidate_count}</strong><span>CVE candidates</span></div><div><strong>MANUAL</strong><span>Invocation mode</span></div></div><pre className="advanced-json">{JSON.stringify(enriched,null,2)}</pre></>}
      </section>}
      {tab==='reports' && <section className="advanced-panel">
        <div className="advanced-heading"><div><span className="eyebrow">VDP-STYLE · FINDING-CENTRIC</span><h2>Report review workspace</h2><p>Every generated section is a separate decision. Pending is not approval; removed components remain in the audit record but are excluded from the final PDF.</p></div>{report && <span className={`advanced-badge ${report.status==='APPROVED'?'approved':''}`}>{report.status}</span>}</div>
        {!report ? <div className="advanced-empty"><h3>No draft loaded</h3><p>Run optional CPE enrichment and choose “Create report draft from enrichment”.</p><button className="ops-btn primary" disabled={!enriched || busy} onClick={createReport}>Create report draft</button></div> : <>
          <div className="advanced-report-summary"><div><strong>{counts.accepted}</strong><span>Included</span></div><div><strong>{counts.removed}</strong><span>Removed</span></div><div><strong>{counts.pending}</strong><span>Pending review</span></div><div><strong>{report.components.length}</strong><span>Total components</span></div></div>
          {report.components.map(c=><article className="report-component" key={c.id}>
            <div className="report-component-head"><div><span className="report-kind">{c.kind}</span><h3>{c.title}</h3></div><span className={`report-status ${c.status.toLowerCase()}`}>{c.status}</span></div>
            {editing===c.id ? <textarea rows={8} value={editText} onChange={e=>setEditText(e.target.value)}/> : <p className="report-content">{c.content}</p>}
            {c.cve && <small className="report-caveat">CVE candidate · {c.cve.status} · {c.cve.confidence} confidence · not proof of exploitability</small>}
            {c.evidence?.length ? <details><summary>Evidence references</summary><pre>{JSON.stringify(c.evidence,null,2)}</pre></details>:null}
            {report.status!=='APPROVED' && <div className="report-component-actions">
              {editing===c.id ? <><button className="ops-btn primary" onClick={()=>decideComponent(c,'EDITED')}>Save edit</button><button className="ops-btn ghost" onClick={()=>setEditing(null)}>Cancel</button></> :
                <><button className="ops-btn primary" onClick={()=>decideComponent(c,'ACCEPTED')}>Accept</button><button className="ops-btn ghost" onClick={()=>{setEditing(c.id);setEditText(c.content)}}>Edit</button><button className="ops-btn danger" onClick={()=>decideComponent(c,'REMOVED')}>Remove</button><button className="ops-btn ghost" onClick={()=>decideComponent(c,'PENDING')}>Leave pending</button></>}
            </div>}
          </article>)}
          <div className="advanced-finalize"><div><strong>{counts.pending===0?'Ready for final approval':'Review required'}</strong><span>{counts.pending} component(s) still pending. All must be reviewed.</span></div>
            {report.status==='APPROVED' ? <button className="ops-btn primary" onClick={downloadReport}>Download approved PDF</button> : <button className="ops-btn primary" disabled={busy || counts.pending>0} onClick={approveReport}>Approve final report</button>}
          </div>
        </>}
      </section>}
      {tab==='autonomous' && <section className="advanced-panel">
        <div className="advanced-heading"><div><span className="eyebrow">SUPERVISED · SCAN-ONLY</span><h2>Autonomous assessment</h2><p>Gemini may propose follow-up Nmap service-discovery scans only. Every operation passes GATE and the scanner's one-use signed authorization. No injection, exploitation, authentication attacks or state-changing tests.</p></div><span className="advanced-badge">HUMAN START / STOP</span></div>
        {!autoSession || ['COMPLETED','FAILED','STOPPED'].includes(autoSession.status) ? <div className="auto-start">
          <label className="advanced-field">Approved TCP ports<input value={autoPorts} onChange={e=>setAutoPorts(e.target.value)}/></label>
          <button className="ops-btn primary" disabled={busy} onClick={startAuto}>Start autonomous scan-only mode</button>
        </div> : <div className="auto-live">
          <div className="auto-live-head"><div><span className="eyebrow">SESSION {autoSession.id}</span><h3>{autoSession.status}</h3><p>Target: {autoSession.target || target}</p></div><button className="ops-btn danger" disabled={busy || autoSession.stop_requested} onClick={stopAuto}>STOP SESSION</button></div>
          <div className="auto-event-list">{(autoSession.events||[]).slice().reverse().map((e:any)=><article key={e.id}><time>{new Date(e.at).toLocaleTimeString()}</time><strong>{e.type.replaceAll('_',' ')}</strong><span>{e.message}</span>{e.data && Object.keys(e.data).length>0 && <details><summary>Details</summary><pre>{JSON.stringify(e.data,null,2)}</pre></details>}</article>)}</div>
          {autoSession.error && <div className="advanced-alert error">{autoSession.error}</div>}
          <p className="auto-stop-note">Stop prevents subsequent scans. A scanner subprocess already in progress may finish before the session exits.</p>
        </div>}
        <div className="auto-safety"><strong>Autonomous policy</strong><ul><li>Nmap TCP service discovery only.</li><li>Gemini follow-up ports must be within the human-approved port list.</li><li>Each scan is independently re-authorized by GATE.</li><li>Maximum four scan operations per session.</li><li>Any operation outside the allowlist is rejected, never silently executed.</li></ul></div>
      </section>}
    </div>
  </main></div>
}
