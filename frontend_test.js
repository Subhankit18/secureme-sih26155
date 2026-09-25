
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const newAnalysisBtn = document.getElementById('newAnalysisBtn');
    const downloadJsonBtn = document.getElementById('downloadJsonBtn');
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');
    const copyJsonBtn = document.getElementById('copyJsonBtn');
    const uploadMeta = document.getElementById('uploadMeta');
    const statusMsg = document.getElementById('statusMsg');
    const reauditBtn = document.getElementById('reauditBtn');

    const allowed = ['.conf','.cfg','.txt','.log'];
    let currentData = null;
    let currentFilter = 'ALL';
    let currentReviews = [];

    const themeBtn = document.getElementById('themeBtn');

    function applyTheme(theme){
      const dark = theme === 'dark';
      document.body.classList.toggle('dark', dark);
      if(themeBtn){
        themeBtn.textContent = dark ? 'Light mode' : 'Dark mode';
        themeBtn.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
      }
      localStorage.setItem('secureme-theme', dark ? 'dark' : 'light');
    }

    applyTheme(localStorage.getItem('secureme-theme') === 'dark' ? 'dark' : 'light');

    if(themeBtn){
      themeBtn.addEventListener('click', ()=>{
        applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark');
      });
    }

    function esc(v){
      return String(v ?? '')
        .replaceAll('&','&amp;')
        .replaceAll('<','&lt;')
        .replaceAll('>','&gt;')
        .replaceAll('"','&quot;')
        .replaceAll("'","&#039;");
    }

    function safeJson(v){
      try { return JSON.stringify(v); } catch { return String(v ?? ''); }
    }

    function severityClass(sev){
      const s = String(sev || 'INFO').toLowerCase();
      return `sev-${s}`;
    }

    function setStatus(text, error=false){
      statusMsg.textContent = text || '';
      statusMsg.className = error ? 'status-msg error' : 'status-msg';
    }

    function fmtBytes(bytes){
      if(bytes < 1024) return `${bytes} B`;
      if(bytes < 1024*1024) return `${(bytes/1024).toFixed(1)} KB`;
      return `${(bytes/(1024*1024)).toFixed(1)} MB`;
    }

    fileInput.addEventListener('change', ()=>{
      const f = fileInput.files[0];
      if(!f){
        uploadMeta.textContent = 'Supported: .conf, .cfg, .txt, .log';
        return;
      }
      const ok = allowed.some(x => f.name.toLowerCase().endsWith(x));
      if(!ok){
        fileInput.value = '';
        uploadMeta.textContent = 'Unsupported file type.';
        setStatus('Use a .conf, .cfg, .txt, or .log configuration file.', true);
        return;
      }
      uploadMeta.textContent = `${f.name} • ${fmtBytes(f.size)} • ready for analysis`;
      setStatus('');
    });

    function clearDashboard(){
      currentData = null;
      currentReviews = [];
      reauditBtn.disabled = true;
      fileInput.value = '';
      uploadMeta.textContent = 'Supported: .conf, .cfg, .txt, .log';
      setStatus('');
      downloadJsonBtn.disabled = true;
      downloadPdfBtn.disabled = true;
      document.getElementById('kpiRisk').textContent='—';
      document.getElementById('kpiRiskFoot').textContent='No analysis loaded';
      document.getElementById('kpiCompliance').textContent='—';
      document.getElementById('kpiComplianceFoot').textContent='Pass rate';
      document.getElementById('kpiFail').textContent='—';
      document.getElementById('kpiUnknown').textContent='—';
      document.getElementById('kpiVendor').textContent='—';
      document.getElementById('kpiVendorFoot').textContent='Detection pending';
      ['kpiRiskBar','kpiComplianceBar','kpiFailBar','kpiUnknownBar','kpiVendorBar'].forEach(id=>document.getElementById(id).style.width='0%');
      document.getElementById('donutPass').style.strokeDasharray='0 100';
      document.getElementById('donutFail').style.strokeDasharray='0 100';
      document.getElementById('donutUnknown').style.strokeDasharray='0 100';
      document.getElementById('donutPass').style.strokeDashoffset='0';
      document.getElementById('donutFail').style.strokeDashoffset='0';
      document.getElementById('donutUnknown').style.strokeDashoffset='0';
      document.getElementById('donutValue').textContent='—';
      document.getElementById('legendPass').textContent='0';
      document.getElementById('legendFail').textContent='0';
      document.getElementById('legendUnknown').textContent='0';
      document.getElementById('compliancePanelMeta').textContent='No analysis loaded';
      document.getElementById('analysisMeta').textContent='—';
      document.getElementById('severityBars').innerHTML='<div class="muted">Run an analysis to display severity.</div>';
      document.getElementById('riskList').innerHTML='<div class="muted">Run an analysis to display risk by finding.</div>';
      document.getElementById('deviceGrid').innerHTML='<div class="muted" style="grid-column:1/-1;padding:12px">No device data.</div>';
      document.getElementById('findingMeta').textContent='0 findings';
      document.getElementById('findingsBody').innerHTML='<tr><td colspan="7" class="muted">Run an analysis to load findings.</td></tr>';
      document.getElementById('unknownCount').textContent='0 items';
      document.getElementById('unknownList').innerHTML='<div class="muted">No unknown configuration lines.</div>';
      document.getElementById('aiContent').innerHTML='<span class="muted">AI assistance will appear when returned by the analysis service.</span>';
      document.getElementById('jsonOutput').textContent='No analysis loaded.';
    }

    function drawDonut(pass, fail, unknown, total){
      if(!total){
        ['donutPass','donutFail','donutUnknown'].forEach(id=>{
          document.getElementById(id).style.strokeDasharray='0 100';
          document.getElementById(id).style.strokeDashoffset='0';
        });
        document.getElementById('donutValue').textContent='0';
        return;
      }
      const p = pass / total * 100;
      const f = fail / total * 100;
      const u = unknown / total * 100;
      document.getElementById('donutPass').style.strokeDasharray=`${p} ${100-p}`;
      document.getElementById('donutPass').style.strokeDashoffset='0';
      document.getElementById('donutFail').style.strokeDasharray=`${f} ${100-f}`;
      document.getElementById('donutFail').style.strokeDashoffset=`-${p}`;
      document.getElementById('donutUnknown').style.strokeDasharray=`${u} ${100-u}`;
      document.getElementById('donutUnknown').style.strokeDashoffset=`-${p+f}`;
      document.getElementById('donutValue').textContent=String(total);
    }

    function renderKpis(data){
      const s=data.summary || {};
      const total=Number(s.total_controls||0);
      const pass=Number(s.pass||0);
      const fail=Number(s.fail||0);
      const unknown=Number(s.unknown||0);
      const score=Number(s.overall_risk_score||0);
      const vendor=String(data.vendor_detection?.vendor || data.normalized?.device?.vendor || 'UNKNOWN').toUpperCase();
      const compliance=total ? (pass/total)*100 : 0;

      document.getElementById('kpiRisk').textContent=Number.isFinite(score)?score.toFixed(1):'—';
      document.getElementById('kpiRiskFoot').textContent=String(s.overall_risk_level || 'INFORMATIONAL');
      document.getElementById('kpiCompliance').textContent=`${compliance.toFixed(0)}%`;
      document.getElementById('kpiComplianceFoot').textContent=`${pass} of ${total} controls passed`;
      document.getElementById('kpiFail').textContent=String(fail);
      document.getElementById('kpiUnknown').textContent=String(unknown);
      document.getElementById('kpiVendor').textContent=vendor;
      document.getElementById('kpiVendorFoot').textContent=String(data.vendor_detection?.method || 'Detection');

      document.getElementById('kpiRiskBar').style.width=`${Math.max(0,Math.min(100,score))}%`;
      document.getElementById('kpiComplianceBar').style.width=`${Math.max(0,Math.min(100,compliance))}%`;
      document.getElementById('kpiFailBar').style.width=`${Math.max(0,Math.min(100,total ? (fail/total)*100 : 0))}%`;
      document.getElementById('kpiUnknownBar').style.width=`${Math.max(0,Math.min(100,total ? (unknown/total)*100 : 0))}%`;
      document.getElementById('kpiVendorBar').style.width=data.vendor_detection?.confidence != null ? `${Math.max(0,Math.min(100,Number(data.vendor_detection.confidence)*100))}%`:'0%';

      document.getElementById('legendPass').textContent=String(pass);
      document.getElementById('legendFail').textContent=String(fail);
      document.getElementById('legendUnknown').textContent=String(unknown);
      document.getElementById('compliancePanelMeta').textContent=`${compliance.toFixed(0)}% compliance`;
    }

    function renderSeverity(data){
      const sc=data.summary?.severity_counts || {};
      const rows=[
        ['CRITICAL',Number(sc.CRITICAL||0),'#812f38'],
        ['HIGH',Number(sc.HIGH||0),'#a3532a'],
        ['MEDIUM',Number(sc.MEDIUM||0),'#a47d27'],
        ['LOW',Number(sc.LOW||0),'#527e9f'],
        ['INFO',Number(sc.INFO||0),'#748394']
      ];
      const max=Math.max(1,...rows.map(r=>r[1]));
      document.getElementById('severityBars').innerHTML=rows.map(([name,count,color])=>`
        <div class="bar-row">
          <div class="bar-label">${name}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count/max)*100}%;background:${color}"></div></div>
          <div class="bar-number">${count}</div>
        </div>`).join('');
    }

    function displayControl(v){
      return String(v ?? '').replace(/^DEMO[-_]?/i,'');
    }

    function renderRiskList(data){
      const findings=Array.isArray(data.findings)?data.findings:[];
      const scored=findings.filter(f=>f.risk_score != null).sort((a,b)=>Number(b.risk_score)-Number(a.risk_score));
      if(!scored.length){
        document.getElementById('riskList').innerHTML='<div class="muted">No scored findings in this analysis.</div>';
        return;
      }
      const max=Math.max(100,...scored.map(f=>Number(f.risk_score)||0));
      document.getElementById('riskList').innerHTML=scored.map(f=>{
        const score=Number(f.risk_score)||0;
        return `<div class="risk-item">
          <div>
            <div class="risk-control">${esc(displayControl(f.control_id || 'Control'))}</div>
            <div class="risk-id">${esc(f.finding_id || '')}</div>
          </div>
          <div class="risk-bar"><span style="width:${Math.max(0,Math.min(100,score/max))*100}%"></span></div>
          <div class="risk-num">${score.toFixed(1)}</div>
        </div>`;
      }).join('');
    }

    function renderDevice(data){
      const d=data.normalized?.device || {};
      const det=data.vendor_detection || {};
      const items=[
        ['Hostname',d.hostname || 'Not available'],
        ['Vendor',d.vendor || det.vendor || 'UNKNOWN'],
        ['Model',d.model || 'Not available'],
        ['Serial',d.serial || 'Not available'],
        ['Detection',det.method || 'Not available'],
        ['Confidence',typeof det.confidence==='number'?`${(det.confidence*100).toFixed(0)}%`:'Not available']
      ];
      document.getElementById('deviceGrid').innerHTML=items.map(([k,v])=>`
        <div class="device-cell">
          <div class="device-label">${esc(k)}</div>
          <div class="device-value">${esc(v)}</div>
        </div>`).join('');
      document.getElementById('analysisMeta').textContent=`${data.source_file || 'configuration'} • ${data.analysis_id || ''}`;
    }

    function renderFindings(data){
      const all=Array.isArray(data.findings)?data.findings:[];
      const filtered=currentFilter==='ALL'?all:all.filter(f=>String(f.status||'UNKNOWN').toUpperCase()===currentFilter);
      document.getElementById('findingMeta').textContent=`${filtered.length} shown • ${all.length} total`;
      if(!filtered.length){
        document.getElementById('findingsBody').innerHTML='<tr><td colspan="7" class="muted">No findings match this filter.</td></tr>';
        return;
      }

      document.getElementById('findingsBody').innerHTML=filtered.map(f=>{
        const status=String(f.status||'UNKNOWN').toUpperCase();
        const severity=String(f.severity||'INFO').toUpperCase();
        const score=f.risk_score==null?'N/A':`${Number(f.risk_score).toFixed(1)} / 100`;
        const p=f.risk_parameters || {};
        const cls=status==='PASS'?'pass':status==='FAIL'?'fail':'unknown';
        return `<tr>
          <td>
            <div class="control-name">${esc(displayControl(f.control_id || 'Control'))}</div>
            <div class="control-id">${esc(f.finding_id || '')} • ${esc(f.framework || '')}</div>
          </td>
          <td><span class="status ${cls}">${esc(status)}</span></td>
          <td class="${severityClass(severity)}">${esc(severity)}</td>
          <td>
            <strong>${esc(score)}</strong>
            <div class="param-line">${esc(f.risk_level || 'UNKNOWN')}</div>
          </td>
          <td>
            <div class="wrap"><strong>Observed</strong><br>${esc(safeJson(f.observed_value))}</div>
            <div class="wrap" style="margin-top:6px"><strong>Expected</strong><br>${esc(safeJson(f.expected_value))}</div>
          </td>
          <td><div class="wrap">${esc(f.evidence || 'No evidence supplied')}</div></td>
          <td>
            <div class="wrap">${esc(f.remediation_reference || 'No remediation supplied')}</div>
            <div class="param-line">S:${esc(p.severity ?? 'N/A')}/5 · L:${esc(p.likelihood ?? 'N/A')}/5 · I:${esc(p.impact ?? 'N/A')}/5 · E:${esc(p.exposure ?? 'N/A')}/5 · X:${esc(p.exploitability ?? 'N/A')}/5</div>
          </td>
        </tr>`;
      }).join('');
    }

    const NORMALIZED_FIELDS = [
      'ssh_version',
      'vty_telnet_enabled',
      'logging_host_configured',
      'password_min_length',
      'hostname_configured',
      'enable_secret_configured',
      'enable_password_legacy_present',
      'weak_local_password_count',
      'login_block_configured',
      'login_delay_seconds',
      'login_on_failure_log',
      'login_on_success_log',
      'aaa_new_model',
      'aaa_login_configured',
      'aaa_authorization_exec_configured',
      'aaa_command_authorization_configured',
      'aaa_exec_accounting_configured',
      'aaa_command_accounting_configured',
      'console_exec_timeout_configured',
      'aux_disabled',
      'vty_exec_timeout_configured',
      'vty_ssh_enabled',
      'vty_access_class_configured',
      'vty_authentication_configured',
      'warning_banner_configured',
      'ssh_authentication_retries',
      'ssh_timeout_seconds',
      'ssh_source_interface',
      'ssh_rsa_key_configured',
      'http_server_enabled',
      'http_access_class_configured',
      'service_password_recovery_enabled',
      'tcp_keepalives_in',
      'tcp_keepalives_out',
      'service_config_enabled',
      'service_pad_enabled',
      'tcp_small_servers_enabled',
      'udp_small_servers_enabled',
      'ip_finger_enabled',
      'ip_bootp_server_enabled',
      'cdp_global_disabled',
      'lldp_global_disabled',
      'vstack_enabled',
      'logging_enabled',
      'logging_buffered_configured',
      'logging_console_configured',
      'logging_monitor_configured',
      'logging_host_configured',
      'logging_source_interface',
      'ntp_enabled',
      'ntp_authenticated',
      'ntp_source_interface',
      'snmp_configured',
      'snmp_community_configured',
      'archive_configured',
      'config_mode_password_configured',
      'copp_configured',
      'cppr_configured',
      'ip_source_route_enabled',
      'ip_redirects_enabled',
      'ip_unreachables_enabled',
      'ip_proxy_arp_enabled',
      'urpf_configured',
      'ip_source_guard_configured',
      'dhcp_snooping_configured',
      'dynamic_arp_inspection_configured',
      'port_security_configured',
      'netflow_configured',
      'acl_count',
      'acl_applied_count',
      'eigrp_configured',
      'ospf_configured',
      'rip_configured',
      'bgp_configured',
      'fhrp_configured',
      'ssh_enabled',
      'telnet_enabled'
    ];

    function normalizedFieldOptions(selected=''){
      return NORMALIZED_FIELDS.map(field =>
        `<option value="${esc(field)}" ${field === selected ? 'selected' : ''}>${esc(field)}</option>`
      ).join('');
    }

    async function loadReviews(analysisId, lines){
      const container = document.getElementById('unknownList');

      try{
        const res = await fetch(
          `/api/v1/analyses/${encodeURIComponent(analysisId)}/reviews`
        );

        if(!res.ok) throw new Error('Unable to load review records.');

        currentReviews = await res.json();

        container.innerHTML = lines.map(line => {
          const review = currentReviews.find(
            r => Number(r.line_number) === Number(line.line_number)
          );
          return renderReviewItem(line, review);
        }).join('');

      }catch(err){
        currentReviews = [];
        container.innerHTML =
          `<div class="review-empty">${esc(err.message)}</div>`;
      }
    }

    function renderReviewItem(line, review){
      const status = String(review?.status || 'PENDING').toUpperCase();
      const statusClass =
        status === 'APPROVED' ? 'approved' :
        status === 'REJECTED' ? 'rejected' : 'pending';

      const locked = status === 'APPROVED' || status === 'REJECTED';
      const disabled = locked ? 'disabled' : '';
      const reviewId = review?.id || '';

      const aiCategory = review?.ai_category || 'N/A';
      const aiInterpretation =
        review?.ai_interpretation || 'No AI interpretation available.';
      const confidence =
        review?.ai_confidence != null
          ? Number(review.ai_confidence).toFixed(2)
          : 'N/A';

      const normalizedValue =
        review?.normalized_value?.value ?? '';

      return `
        <div class="review-item" data-review-id="${esc(reviewId)}">

          <div class="review-head">
            <div class="review-line">LINE ${esc(line.line_number)}</div>
            <div class="review-line">${esc(status)}</div>
          </div>

          <div class="review-cmd">${esc(line.source)}</div>

          <div class="review-meta">
            AI Category: ${esc(aiCategory)}
            · Confidence: ${esc(confidence)}
          </div>

          <div class="review-meta">
            ${esc(aiInterpretation)}
          </div>

          ${reviewId ? `
          <div class="review-actions">
            <select id="field-${esc(reviewId)}" ${disabled}>
              <option value="">Select normalized field</option>
              ${normalizedFieldOptions(review?.normalized_field || '')}
            </select>

            <input
              id="value-${esc(reviewId)}"
              type="text"
              placeholder="Normalized value"
              value="${esc(normalizedValue)}"
              ${disabled}
            />

            <button
              class="review-btn approve"
              onclick="approveReview('${esc(reviewId)}')"
              ${disabled}>
              Approve
            </button>

            <button
              class="review-btn reject"
              onclick="rejectReview('${esc(reviewId)}')"
              ${disabled}>
              Reject
            </button>
          </div>
          ` : `
          <div class="review-status pending">
            No database review record exists for this line.
          </div>
          `}

          <div class="review-status ${statusClass}">
            ${status === 'APPROVED'
              ? `Approved by ${esc(review?.reviewed_by || 'reviewer')}`
              : status === 'REJECTED'
                ? `Rejected by ${esc(review?.reviewed_by || 'reviewer')}`
                : 'Awaiting human review'}
          </div>
        </div>
      `;
    }

    function getReviewer(){
      const value = window.prompt('Enter reviewer name:', 'member2');
      if(value === null) return null;
      const reviewer = value.trim();
      if(!reviewer){
        setStatus('Reviewer name is required.', true);
        return null;
      }
      return reviewer;
    }

    async function approveReview(reviewId){
      if(!reviewId) return;

      const reviewer = getReviewer();
      if(!reviewer) return;

      const fieldEl = document.getElementById(`field-${reviewId}`);
      const valueEl = document.getElementById(`value-${reviewId}`);

      const normalizedField = fieldEl?.value || null;
      const rawValue = valueEl?.value ?? '';

      let normalizedValue = null;

      if(normalizedField && rawValue.trim() !== ''){
        const parsed = parseNormalizedValue(rawValue.trim());
        normalizedValue = {value: parsed};
      }

      try{
        setStatus('Approving review...');

        const res = await fetch(
          `/api/v1/reviews/${encodeURIComponent(reviewId)}/approve`,
          {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({
              reviewed_by: reviewer,
              normalized_field: normalizedField,
              normalized_value: normalizedValue
            })
          }
        );

        const data = await res.json().catch(()=>({}));

        if(!res.ok){
          throw new Error(data.detail || `Approval failed (${res.status}).`);
        }

        setStatus('Review approved.');
        await refreshReviews();

      }catch(err){
        setStatus(err?.message || 'Approval failed.', true);
      }
    }

    async function rejectReview(reviewId){
      if(!reviewId) return;

      const reviewer = getReviewer();
      if(!reviewer) return;

      try{
        setStatus('Rejecting review...');

        const res = await fetch(
          `/api/v1/reviews/${encodeURIComponent(reviewId)}/reject`,
          {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({
              reviewed_by: reviewer
            })
          }
        );

        const data = await res.json().catch(()=>({}));

        if(!res.ok){
          throw new Error(data.detail || `Rejection failed (${res.status}).`);
        }

        setStatus('Review rejected.');
        await refreshReviews();

      }catch(err){
        setStatus(err?.message || 'Rejection failed.', true);
      }
    }

    function parseNormalizedValue(raw){
      const lower = raw.toLowerCase();

      if(lower === 'true') return true;
      if(lower === 'false') return false;

      if(/^-?\d+(?:\.\d+)?$/.test(raw)){
        const n = Number(raw);
        if(Number.isFinite(n)) return n;
      }

      return raw;
    }

    async function refreshReviews(){
      if(!currentData?.analysis_id) return;

      const lines = Array.isArray(currentData.normalized?.unknown_lines)
        ? currentData.normalized.unknown_lines
        : [];

      if(!lines.length){
        document.getElementById('unknownList').innerHTML =
          '<div class="muted">No unknown configuration lines.</div>';
        return;
      }

      await loadReviews(currentData.analysis_id, lines);
    }

    async function reauditCurrent(){
      if(!currentData?.analysis_id) return;

      const approved = currentReviews.filter(
        r => String(r.status).toUpperCase() === 'APPROVED'
      );

      if(!approved.length){
        setStatus('Approve at least one review before re-audit.', true);
        return;
      }

      reauditBtn.disabled = true;
      const old = reauditBtn.textContent;
      reauditBtn.textContent = 'Re-auditing...';

      try{
        setStatus('Running deterministic re-audit...');

        const res = await fetch(
          `/api/v1/analyses/${encodeURIComponent(currentData.analysis_id)}/reaudit`,
          {method:'POST'}
        );

        const data = await res.json().catch(()=>({}));

        if(!res.ok){
          throw new Error(data.detail || `Re-audit failed (${res.status}).`);
        }

        render(data);
        setStatus(
          `Re-audit completed. Applied ${Number(data.summary?.applied_review_mappings || 0)} approved mapping(s).`
        );

        document.getElementById('overview')
          .scrollIntoView({behavior:'smooth',block:'start'});

      }catch(err){
        setStatus(err?.message || 'Re-audit failed.', true);
      }finally{
        reauditBtn.disabled = false;
        reauditBtn.textContent = old;
      }
    }

    function renderUnknown(data){
      const lines = Array.isArray(data.normalized?.unknown_lines)
        ? data.normalized.unknown_lines
        : [];

      document.getElementById('unknownCount').textContent =
        `${lines.length} item${lines.length === 1 ? '' : 's'}`;

      reauditBtn.disabled = !data.analysis_id;

      if(!lines.length){
        document.getElementById('unknownList').innerHTML =
          '<div class="muted">No unknown configuration lines.</div>';
        return;
      }

      loadReviews(data.analysis_id, lines);
    }

    function renderAI(data){
      const ai=data.ai;
      if(!ai){
        document.getElementById('aiContent').innerHTML='<span class="muted">No AI assistance returned.</span>';
        return;
      }
      if(ai.status==='SKIPPED'){
        document.getElementById('aiContent').innerHTML=`
          <div class="ai-box"><h4>Status</h4><p>${esc(ai.reason || 'AI assistance was not used.')}</p></div>`;
        return;
      }
      const items=Array.isArray(ai.unknown_command_interpretations)?ai.unknown_command_interpretations:[];
      document.getElementById('aiContent').innerHTML=`
        <div class="ai-grid">
          <div class="ai-box"><h4>Summary</h4><p>${esc(ai.summary || 'No summary returned.')}</p></div>
          <div class="ai-box"><h4>Risk explanation</h4><p>${esc(ai.risk_explanation || 'No explanation returned.')}</p></div>
          <div class="ai-box"><h4>Remediation</h4><p>${esc(ai.remediation || 'No remediation returned.')}</p></div>
        </div>
        ${items.length ? `<div style="margin-top:10px"><div class="field-label">Unknown-command interpretation</div>${items.map(item=>`
          <div class="review-item">
            <div class="review-head">
              <div class="review-line">LINE ${esc(item.line_number)}</div>
              <div class="review-line">CONFIDENCE ${typeof item.confidence==='number'?item.confidence.toFixed(2):'N/A'}</div>
            </div>
            <div class="review-cmd">${esc(item.command || '')}</div>
            <div class="review-meta">Category: ${esc(item.suggested_category || 'N/A')} · Value: ${esc(item.suggested_value || 'N/A')}</div>
            <div class="review-meta">${esc(item.explanation || '')}</div>
          </div>`).join('')}</div>`:''}`;
    }

    function render(data){
      currentData=data;
      downloadJsonBtn.disabled=false;
      downloadPdfBtn.disabled=false;

      const s=data.summary || {};
      const total=Number(s.total_controls||0);
      const pass=Number(s.pass||0);
      const fail=Number(s.fail||0);
      const unknown=Number(s.unknown||0);

      renderKpis(data);
      drawDonut(pass,fail,unknown,total);
      renderSeverity(data);
      renderRiskList(data);
      renderDevice(data);
      renderFindings(data);
      renderUnknown(data);
      renderAI(data);
      document.getElementById('jsonOutput').textContent=JSON.stringify(data.normalized || {}, null, 2);
    }

    document.querySelectorAll('.filter').forEach(btn=>{
      btn.addEventListener('click',()=>{
        currentFilter=btn.dataset.filter;
        document.querySelectorAll('.filter').forEach(b=>b.classList.toggle('active',b===btn));
        if(currentData) renderFindings(currentData);
      });
    });

    analyzeBtn.addEventListener('click',async()=>{
      const file=fileInput.files[0];
      if(!file){
        setStatus('Choose a configuration file first.',true);
        return;
      }
      if(!allowed.some(x=>file.name.toLowerCase().endsWith(x))){
        setStatus('Unsupported file type. Use .conf, .cfg, .txt, or .log.',true);
        return;
      }

      analyzeBtn.disabled=true;
      setStatus('Analyzing configuration…');

      const form=new FormData();
      form.append('file',file);

      try{
        const res=await fetch('/api/v1/analyses',{method:'POST',body:form});
        let data={};
        try{data=await res.json()}catch{}
        if(!res.ok) throw new Error(data.detail || `Analysis failed (${res.status}).`);
        render(data);
        setStatus('Analysis completed.');
        document.getElementById('overview').scrollIntoView({behavior:'smooth',block:'start'});
      }catch(err){
        setStatus(err?.message || 'Analysis failed.',true);
      }finally{
        analyzeBtn.disabled=false;
      }
    });

    copyJsonBtn.addEventListener('click',async()=>{
      if(!currentData) return;
      try{
        await navigator.clipboard.writeText(JSON.stringify(currentData.normalized || {}, null, 2));
        const old=copyJsonBtn.textContent;
        copyJsonBtn.textContent='Copied';
        setTimeout(()=>copyJsonBtn.textContent=old,900);
      }catch{
        setStatus('Clipboard access is unavailable.',true);
      }
    });

    downloadJsonBtn.addEventListener('click',()=>{
      if(!currentData) return;
      const blob=new Blob([JSON.stringify(currentData,null,2)],{type:'application/json'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');
      a.href=url;
      a.download=`secureme-analysis-${currentData.analysis_id || 'result'}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });


    downloadPdfBtn.addEventListener('click',async()=>{
      if(!currentData?.analysis_id) return;
      downloadPdfBtn.disabled=true;
      const old=downloadPdfBtn.textContent;
      downloadPdfBtn.textContent='Generating…';
      try{
        const res=await fetch(`/api/v1/analyses/${encodeURIComponent(currentData.analysis_id)}/pdf`);
        if(!res.ok){
          let message='PDF generation failed.';
          try{
            const data=await res.json();
            message=data.detail || message;
          }catch{}
          throw new Error(message);
        }
        const blob=await res.blob();
        const url=URL.createObjectURL(blob);
        const a=document.createElement('a');
        a.href=url;
        a.download=`secureme-analysis-${currentData.analysis_id}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }catch(err){
        setStatus(err?.message || 'PDF download failed.',true);
      }finally{
        downloadPdfBtn.disabled=false;
        downloadPdfBtn.textContent=old;
      }
    });

    reauditBtn.addEventListener('click', reauditCurrent);

    newAnalysisBtn.addEventListener('click',()=>{
      clearDashboard();
      window.scrollTo({top:0,behavior:'smooth'});
      fileInput.focus();
    });
  