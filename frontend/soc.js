(() => {
  const $ = id => document.getElementById(id);
  const API = '/soc-api';
  let selectedCase = null;
  let detail = null;
  let caseDraftDirty = false;

  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const percent = value => value == null ? 'N/A' : `${(Number(value) * 100).toFixed(1)}%`;
  const duration = value => value == null ? 'N/A' : Number(value) < 60 ? `${Number(value).toFixed(1)}s` : `${(Number(value) / 60).toFixed(1)}m`;
  const dateText = value => value ? new Date(value).toLocaleString() : '—';

  async function api(path, options = {}) {
    const response = await fetch(`${API}${path}`, {headers:{'Accept':'application/json','Content-Type':'application/json'}, cache:'no-store', ...options});
    const body = await response.text();
    let data; try { data = body ? JSON.parse(body) : null; } catch { data = {detail: body}; }
    if (!response.ok) throw new Error(data?.detail?.error || data?.detail || `HTTP ${response.status}`);
    return data;
  }

  async function loadMetrics() {
    try {
      const result = await api('/metrics');
      const metrics = result.metrics || {}, sizes = result.sample_sizes || {};
      $('metric-alert-case').textContent = percent(metrics.alert_to_case_rate);
      $('metric-alert-case-sample').textContent = `${sizes.alerts_linked_to_case || 0}/${sizes.alerts_observed || 0} alerts linked to a case`;
      $('metric-duplicates').textContent = percent(metrics.duplicate_rate);
      $('metric-duplicates-sample').textContent = `${sizes.campaign_duplicates_collapsed || 0} requests joined an existing case`;
      $('metric-fp').textContent = percent(metrics.false_positive_rate);
      $('metric-fp-sample').textContent = `${sizes.analyst_labeled_cases || 0} adjudicated cases`;
      $('metric-evidence').textContent = percent(metrics.evidence_completeness);
      $('metric-evidence-sample').textContent = `${sizes.complete_evidence_alerts || 0}/${sizes.alerts_observed || 0} alerts had all sources`;
      $('metric-mtta').textContent = duration(metrics.mtta_seconds_mean);
      $('metric-mtta-sample').textContent = `${sizes.analyst_acknowledged_cases || 0} acknowledged cases`;
      $('metric-mttr').textContent = duration(metrics.mttr_seconds_mean);
      $('metric-mttr-sample').textContent = `${sizes.resolved_cases || 0} resolved cases`;
    } catch (error) {
      $('metric-evidence-sample').textContent = `Metrics unavailable: ${error.message}`;
    }
  }

  function filters() {
    const params = new URLSearchParams();
    for (const [id, name] of [['case-q','q'],['case-severity','severity'],['case-status','status'],['case-route','route']]) {
      const value = $(id).value.trim(); if (value) params.set(name, value);
    }
    for (const [id, name] of [['case-since','since'],['case-until','until']]) {
      const value = $(id).value; if (value) params.set(name, new Date(value).toISOString());
    }
    params.set('limit','200');
    return params;
  }

  function renderRows(cases) {
    $('case-count').textContent = `${cases.length} case${cases.length === 1 ? '' : 's'}`;
    if (!cases.length) {
      $('case-rows').innerHTML = '<tr><td colspan="6" class="soc-empty">No matching cases. Anomalous evidence is correlated automatically when all three sources arrive.</td></tr>';
      return;
    }
    $('case-rows').innerHTML = cases.map(item => `
      <tr class="soc-row ${item.case_id === selectedCase ? 'selected' : ''}" data-case-id="${escapeHtml(item.case_id)}">
        <td><span class="soc-pill ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span></td>
        <td><button class="soc-case-link" data-open-case="${escapeHtml(item.case_id)}">${escapeHtml(item.case_id)}</button><span class="soc-route">${escapeHtml(item.route)}</span></td>
        <td><span class="soc-status">${escapeHtml(item.status.replace('_',' '))}</span></td>
        <td>${Number(item.request_count || 1)}</td><td>${escapeHtml(dateText(item.last_seen))}</td><td>${escapeHtml(item.assignee || 'Unassigned')}</td>
      </tr>`).join('');
    $('case-rows').querySelectorAll('[data-open-case]').forEach(button => button.addEventListener('click', () => openCase(button.dataset.openCase)));
    $('case-rows').querySelectorAll('.soc-row').forEach(row => row.addEventListener('click', event => {
      if (!event.target.closest('button')) openCase(row.dataset.caseId);
    }));
  }

  async function loadCases() {
    $('case-error').textContent = '';
    try {
      const cases = await api(`/cases?${filters().toString()}`);
      renderRows(cases);
      if (selectedCase && !cases.some(item => item.case_id === selectedCase)) selectedCase = null;
      if (selectedCase) await openCase(selectedCase, false);
    } catch (error) {
      $('case-error').textContent = `Unable to load cases: ${error.message}`;
      renderRows([]);
    }
  }

  function eventText(item) {
    const fields = [];
    if (item.cache_status) fields.push(`cache ${item.cache_status}`);
    if (item.classification) fields.push(`classification ${item.classification}`);
    if (item.anomaly_score != null) fields.push(`score ${Number(item.anomaly_score).toFixed(3)}`);
    if (item.recommended_cache_action) fields.push(`recommended ${item.recommended_cache_action}`);
    if (item.model_version) fields.push(`model ${item.model_version}`);
    if (item.final_anomaly != null) fields.push(`shadow anomaly ${item.final_anomaly}`);
    if (item.verdict) fields.push(`${item.severity} · ${item.verdict}`);
    if (item.summary) fields.push(item.summary);
    if (item.indicator_codes?.length) fields.push(`indicators: ${item.indicator_codes.join(', ')}`);
    return fields.join(' · ') || `Request ${item.request_id || 'unknown'}`;
  }

  function renderDetail(report, audit) {
    caseDraftDirty = false;
    const c = report.case || {}, technique = report.suspected_technique?.name || 'Unclassified WCP evidence';
    const timeline = [...(report.timeline || [])].sort((a,b) => String(a.timestamp).localeCompare(String(b.timestamp)));
    const mitigation = report.mitigation_suggestions || [];
    const options = mitigation.map(item => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`).join('');
    const notes = (c.notes || []).map(item => `<div class="soc-note"><b>${escapeHtml(item.author)} · ${escapeHtml(dateText(item.timestamp))}</b><br>${escapeHtml(item.text)}</div>`).join('') || '<p class="soc-edit-note">No analyst notes.</p>';
    const decisions = (c.mitigation_decisions || []).map(item => `<div class="soc-note"><b>${escapeHtml(item.decision.replace('_',' '))} · ${escapeHtml(item.reviewer || item.selected_by || 'analyst')}</b><br>${escapeHtml(item.action)}<br><small>${escapeHtml(dateText(item.timestamp))}</small></div>`).join('') || '<p class="soc-edit-note">No mitigation decision recorded.</p>';
    const auditHtml = audit.length ? audit.slice().reverse().map(event => `<p><b>${escapeHtml(event.event_type)}</b> · ${escapeHtml(event.actor)} · ${escapeHtml(dateText(event.timestamp))}<br>${escapeHtml(JSON.stringify(event.details || {}))}</p>`).join('') : '<p>No audit events.</p>';
    $('case-detail').classList.remove('hidden');
    $('case-detail-content').innerHTML = `
      <div class="soc-section-head"><div><span class="eyebrow">CASE DETAIL</span><h2>${escapeHtml(c.case_id)}</h2></div><span class="soc-pill ${escapeHtml(c.severity || report.triage?.severity)}">${escapeHtml(c.severity || report.triage?.severity)}</span></div>
      <p class="soc-detail-summary">${escapeHtml(technique)}<br>${escapeHtml(report.triage?.incident_summary || '')}</p>
      <div class="soc-detail-meta"><div><small>Status</small><b>${escapeHtml((c.status || 'open').replace('_',' '))}</b></div><div><small>Assignee</small><b>${escapeHtml(c.assignee || 'Unassigned')}</b></div><div><small>Route</small><b>${escapeHtml(c.route)}</b></div><div><small>Campaign</small><b>${Number(c.request_count || 1)} request(s) · ${Math.round(Number(c.campaign_window_seconds || 900) / 60)}m window</b></div><div><small>First seen</small><b>${escapeHtml(dateText(c.first_seen))}</b></div><div><small>Last seen</small><b>${escapeHtml(dateText(c.last_seen))}</b></div></div>
      <div class="soc-timeline"><h3>Evidence timeline</h3><div class="soc-timeline-list">${timeline.map(item => `<div class="soc-timeline-item"><b>${escapeHtml(item.source.replace('_',' '))}</b><time>${escapeHtml(dateText(item.timestamp))} · <code>${escapeHtml(item.request_id)}</code></time><p>${escapeHtml(eventText(item))}</p></div>`).join('')}</div></div>
      <div class="soc-edit"><h3>Analyst workflow</h3><div class="soc-edit-grid"><label>Status<select id="edit-status">${['open','investigating','contained','resolved','false_positive'].map(value => `<option value="${value}" ${c.status === value ? 'selected' : ''}>${value.replace('_',' ')}</option>`).join('')}</select></label><label>Assignee<input id="edit-assignee" maxlength="80" value="${escapeHtml(c.assignee || '')}" placeholder="analyst name"></label></div><label>Analyst outcome<select id="edit-label"><option value="">Unlabelled</option><option value="true_positive" ${c.analyst_label === 'true_positive' ? 'selected' : ''}>True positive</option><option value="false_positive" ${c.analyst_label === 'false_positive' ? 'selected' : ''}>False positive</option><option value="inconclusive" ${c.analyst_label === 'inconclusive' ? 'selected' : ''}>Inconclusive</option></select></label><label>New note<textarea id="edit-note" maxlength="1000" placeholder="Record evidence or investigation outcome"></textarea></label><h3>Mitigation review</h3><label>Recommendation<select id="edit-mitigation"><option value="">No mitigation selected</option>${options}</select></label><div class="soc-edit-grid"><label>Decision<select id="edit-decision"><option value="pending_review">Pending review</option><option value="approved">Approved</option><option value="rejected">Rejected</option></select></label><label>Reviewer (required for decision)<input id="edit-reviewer" maxlength="80" placeholder="reviewer name"></label></div><p class="soc-edit-note">Approval is audit-only. The SOC service cannot perform a cache action; apply and verify changes manually using the runbook.</p><div class="soc-edit-actions"><button class="btn primary" id="save-case">Save case updates</button></div></div>
      <div class="soc-edit"><h3>Analyst notes</h3>${notes}<h3>Mitigation decisions</h3>${decisions}</div>
      <div class="soc-audit"><details><summary>Audit trail (${audit.length} events)</summary><div class="soc-audit-list">${auditHtml}</div></details></div>`;
    $('case-detail-content').insertAdjacentHTML('beforeend', `<p class="soc-updated">Last updated ${escapeHtml(dateText(c.updated_at))}</p>`);
    $('case-detail-content').addEventListener('input', () => { caseDraftDirty = true; });
    $('save-case').addEventListener('click', saveCase);
  }

  async function openCase(caseId, fetchReport = true) {
    selectedCase = caseId;
    if (fetchReport) {
      $('case-detail').classList.remove('hidden');
      $('case-detail-content').innerHTML = '<p class="soc-empty">Loading case timeline…</p>';
    }
    try {
      if (fetchReport || !detail || detail.case?.case?.case_id !== caseId) {
        const [report, audit] = await Promise.all([api(`/cases/${encodeURIComponent(caseId)}`), api(`/cases/${encodeURIComponent(caseId)}/audit`)]);
        detail = {case: report, audit};
      }
      renderDetail(detail.case, detail.audit);
      $('case-rows').querySelectorAll('.soc-row').forEach(row => row.classList.toggle('selected', row.dataset.caseId === caseId));
    } catch (error) {
      $('case-detail-content').innerHTML = `<p class="soc-error">Unable to load case: ${escapeHtml(error.message)}</p>`;
    }
  }

  async function saveCase() {
    if (!selectedCase) return;
    const payload = {status:$('edit-status').value, assignee:$('edit-assignee').value, actor:'local-analyst'};
    const label = $('edit-label').value; if (label) payload.analyst_label = label;
    const note = $('edit-note').value.trim(); if (note) payload.note = note;
    const action = $('edit-mitigation').value;
    if (action) {
      payload.mitigation_action = action;
      payload.mitigation_decision = $('edit-decision').value;
      payload.reviewer = $('edit-reviewer').value;
    }
    try {
      const report = await api(`/cases/${encodeURIComponent(selectedCase)}`, {method:'PATCH',body:JSON.stringify(payload)});
      detail = {case:report, audit:await api(`/cases/${encodeURIComponent(selectedCase)}/audit`)};
      renderDetail(detail.case, detail.audit);
      await Promise.all([loadCases(), loadMetrics()]);
      if (window.toast) window.toast('Case and audit trail updated');
    } catch (error) {
      if (window.toast) window.toast(`Update failed: ${error.message}`);
      else alert(`Update failed: ${error.message}`);
    }
  }

  async function refresh() { await Promise.all([loadMetrics(), loadCases()]); }
  $('soc-refresh').addEventListener('click', refresh);
  $('case-search').addEventListener('click', loadCases);
  $('case-q').addEventListener('keydown', event => { if (event.key === 'Enter') loadCases(); });
  document.querySelectorAll('.nav-item[data-panel="soc"]').forEach(button => button.addEventListener('click', refresh));
  window.setInterval(() => {
    const panel = $('soc'), detailPanel = $('case-detail');
    if (panel.classList.contains('active') && !caseDraftDirty && !(detailPanel && detailPanel.contains(document.activeElement))) refresh();
  }, 15000);
  refresh();
})();
