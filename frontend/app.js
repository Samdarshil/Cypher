import { createClient, ApiError } from "./api.js";

const API_BASE = window.CYPHER_API_BASE || window.location.origin;
const localHosts = ["localhost", "127.0.0.1", "::1"];
const remoteApi = !localHosts.includes(new URL(API_BASE, window.location.href).hostname);
const state = {
  investigations: [],
  activeCaseId: null,
  activeCase: null,
  activeTab: "overview",
  connOk: null,
  apiToken: "",
  publicDemo: false,
};
const api = createClient(API_BASE, () => state.apiToken);

const viewRoot = document.getElementById("view-root");
const topbarTitle = document.getElementById("topbar-title");
const activeCaseNav = document.getElementById("active-case-nav");
const activeCaseLabel = document.getElementById("active-case-label");

function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "html") el.innerHTML = v;
    else el.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

function emptyState(icon, title, sub, actionEl) {
  return h("div", { class: "empty-state" }, [
    h("div", { class: "empty-state-icon" }, icon),
    h("div", { class: "empty-state-title" }, title),
    h("div", { class: "empty-state-sub" }, sub),
    actionEl,
  ]);
}

function loadingState(label = "Loading…") {
  return h("div", { class: "loading-state" }, [h("div", { class: "spinner" }), h("div", {}, label)]);
}

function errorState(message, onRetry) {
  const children = [h("div", { class: "empty-state-icon" }, "⚠"), h("div", { class: "empty-state-title" }, "Something went wrong"), h("div", { class: "empty-state-sub" }, message)];
  if (onRetry) children.push(h("button", { class: "btn", onclick: onRetry }, "Retry"));
  return h("div", { class: "error-state" }, children);
}

function badge(text, cls) {
  return h("span", { class: `badge badge-${cls || text}` }, text.replace(/_/g, " "));
}

function toast(message, kind = "info") {
  const stack = document.getElementById("toast-stack");
  const el = h("div", { class: `toast ${kind}` }, message);
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString();
}
function fmtTimeShort(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

async function withLoading(container, fn) {
  container.innerHTML = "";
  container.appendChild(loadingState());
  try {
    await fn();
  } catch (err) {
    container.innerHTML = "";
    const message = err instanceof ApiError ? err.message : String(err);
    container.appendChild(errorState(message, () => withLoading(container, fn)));
  }
}

async function checkConnection() {
  const dot = document.getElementById("conn-dot");
  const label = document.getElementById("conn-label");
  try {
    await api.listInvestigations();
    state.connOk = true;
    dot.className = "status-dot ok";
    label.textContent = "Connected";
  } catch (err) {
    state.connOk = false;
    dot.className = "status-dot bad";
    label.textContent = "Backend unreachable";
  }
}

function navigate(hash) {
  window.location.hash = hash;
}

async function router() {
  const hash = window.location.hash || "#/dashboard";
  const parts = hash.replace("#/", "").split("/");

  document.querySelectorAll(".sidebar .nav-item[data-route]").forEach((el) => {
    el.classList.toggle("active", el.dataset.route === "#/" + parts[0]);
  });

  if (parts[0] === "dashboard") {
    setActiveCaseNav(null);
    topbarTitle.textContent = "Dashboard";
    await renderDashboard();
  } else if (parts[0] === "investigations" && !parts[1]) {
    setActiveCaseNav(null);
    topbarTitle.textContent = "Investigations";
    await renderInvestigationsList();
  } else if (parts[0] === "investigations" && parts[1]) {
    const caseId = parts[1];
    const tab = parts[2] || "overview";
    state.activeCaseId = caseId;
    state.activeTab = tab;
    await renderInvestigationDetail(caseId, tab);
  } else {
    navigate("#/dashboard");
  }
}

function setActiveCaseNav(caseSummary) {
  if (!caseSummary) {
    activeCaseNav.hidden = true;
    activeCaseLabel.hidden = true;
    return;
  }
  activeCaseNav.hidden = false;
  activeCaseLabel.hidden = false;
  activeCaseLabel.textContent = caseSummary.name;
  activeCaseNav.querySelectorAll(".nav-item[data-tab]").forEach((el) => {
    el.classList.toggle("active", el.dataset.tab === state.activeTab);
    el.onclick = (e) => {
      e.preventDefault();
      navigate(`#/investigations/${caseSummary.case_id}/${el.dataset.tab}`);
    };
  });
}

async function renderDashboard() {
  await withLoading(viewRoot, async () => {
    const investigations = await api.listInvestigations();
    viewRoot.innerHTML = "";
    viewRoot.appendChild(h("section", { class: "page-intro" }, [
      h("span", { class: "eyebrow" }, "INVESTIGATION WORKSPACE / OVERVIEW"),
      h("h1", {}, "Operational picture"),
      h("p", {}, "Cases, evidence, and analyst activity from your workspace."),
    ]));

    if (investigations.length === 0) {
      viewRoot.appendChild(
        emptyState(
          "▣",
          "No investigations yet",
          "Create an investigation to begin. Cypher won't show any statistics, findings, or activity until real data exists.",
          h("button", { class: "btn btn-primary", onclick: () => openNewInvestigationModal() }, "+ Create Investigation")
        )
      );
      return;
    }

    const open = investigations.filter((c) => c.status === "open" || c.status === "analyzing").length;
    const stats = h("div", { class: "grid grid-cols-3" }, [
      statCard(investigations.length, "Total Investigations"),
      statCard(open, "Active"),
      statCard(investigations.filter((c) => c.status === "closed").length, "Closed"),
    ]);
    viewRoot.appendChild(stats);

    viewRoot.appendChild(h("div", { class: "section-title" }, "Recent Investigations"));
    const list = h("div");
    investigations
      .slice()
      .sort((a, b) => b.updated_at - a.updated_at)
      .slice(0, 8)
      .forEach((c) => list.appendChild(investigationListItem(c)));
    viewRoot.appendChild(list);
  });
}

function statCard(value, label) {
  return h("div", { class: "card stat-card" }, [h("div", { class: "stat-value" }, String(value)), h("div", { class: "stat-label" }, label)]);
}

function investigationListItem(c) {
  return h(
    "div",
    { class: "list-item", onclick: () => navigate(`#/investigations/${c.case_id}`) },
    [
      h("div", { class: "list-item-main" }, [h("div", { class: "list-item-title" }, c.name), h("div", { class: "list-item-sub mono" }, `${c.case_id} · updated ${fmtTime(c.updated_at)}`)]),
      badge(c.status, c.status),
    ]
  );
}

async function renderInvestigationsList() {
  await withLoading(viewRoot, async () => {
    const investigations = await api.listInvestigations();
    viewRoot.innerHTML = "";
    if (investigations.length === 0) {
      viewRoot.appendChild(
        emptyState("▣", "No investigations yet", "Create your first investigation to begin.", h("button", { class: "btn btn-primary", onclick: () => openNewInvestigationModal() }, "+ Create Investigation"))
      );
      return;
    }
    investigations.forEach((c) => viewRoot.appendChild(investigationListItem(c)));
  });
}

async function renderInvestigationDetail(caseId, tab) {
  await withLoading(viewRoot, async () => {
    const c = await api.getInvestigation(caseId);
    state.activeCase = c;
    setActiveCaseNav(c);
    topbarTitle.textContent = c.name;
    viewRoot.innerHTML = "";

    const tabs = ["overview", "evidence", "analysis", "observations", "correlations", "findings", "ai", "timeline", "report"];
    const tabBar = h(
      "div",
      { class: "tab-bar" },
      tabs.map((t) =>
        h("div", { class: `tab-btn ${t === tab ? "active" : ""}`, onclick: () => navigate(`#/investigations/${caseId}/${t}`) }, t[0].toUpperCase() + t.slice(1))
      )
    );
    viewRoot.appendChild(tabBar);

    const body = h("div");
    viewRoot.appendChild(body);

    const renderers = {
      overview: renderOverviewTab, evidence: renderEvidenceTab, analysis: renderAnalysisTab,
      observations: renderObservationsTab, correlations: renderCorrelationsTab,
      findings: renderFindingsTab, ai: renderAiTab, timeline: renderTimelineTab, report: renderReportTab,
    };
    await (renderers[tab] || renderOverviewTab)(caseId, body);
  });
}

async function renderOverviewTab(caseId, body) {
  const [c, evidence, findings, observations] = await Promise.all([
    api.getInvestigation(caseId), api.listEvidence(caseId), api.listFindings(caseId), api.listObservations(caseId),
  ]);
  body.appendChild(h("div", { class: "grid grid-cols-3" }, [
    statCard(evidence.length, "Evidence Items"),
    statCard(observations.length, "Observations"),
    statCard(findings.length, "Findings"),
  ]));
  body.appendChild(h("div", { class: "card" }, [
    h("div", {}, [h("strong", {}, "Description: "), c.description || "(none provided)"]),
    h("div", { style: "margin-top:8px" }, [h("strong", {}, "Status: "), badge(c.status, c.status)]),
    h("div", { style: "margin-top:8px; color:var(--text-2); font-size:12px" }, `Created ${fmtTime(c.created_at)} · Updated ${fmtTime(c.updated_at)}`),
  ]));
  if (evidence.length === 0) {
    body.appendChild(emptyState("▦", "Investigation ready", "Add evidence to begin analysis.", h("button", { class: "btn btn-primary", onclick: () => openAddEvidenceModal(caseId) }, "+ Add Evidence")));
  }
}

async function renderEvidenceTab(caseId, body) {
  const [list, limits] = await Promise.all([api.listEvidence(caseId), api.getUploadLimits()]);
  const fileInput = h("input", { type: "file", multiple: "", id: "evidence-file-input", class: "visually-hidden", "aria-label": "Choose evidence files" });
  const queue = h("div", { class: "upload-queue", "aria-live": "polite" });
  const uploadButton = h("button", { class: "btn btn-primary", disabled: "" }, "Upload selected files");
  const pickerButton = h("button", { class: "btn", onclick: () => fileInput.click() }, "Choose files");
  const dropzone = h("div", { class: "upload-dropzone", tabindex: "0", role: "button", "aria-label": "Choose evidence files or drop files here" }, [
    h("div", { class: "upload-mark", "aria-hidden": "true" }, "＋"),
    h("strong", {}, "Add evidence files"),
    h("span", {}, `Drop files here or use the file picker · Up to ${formatBytes(limits.max_file_bytes)} per file`),
    fileInput,
  ]);
  let selected = [];
  const paintQueue = () => {
    queue.innerHTML = "";
    selected.forEach((file, index) => queue.appendChild(h("div", { class: "upload-row" }, [
      h("div", { class: "upload-file-name" }, [h("strong", {}, file.name), h("span", {}, formatBytes(file.size))]),
      h("button", { class: "btn btn-ghost btn-sm", "aria-label": `Remove ${file.name}`, onclick: () => { selected.splice(index, 1); paintQueue(); } }, "Remove"),
    ])));
    uploadButton.disabled = selected.length === 0 || selected.some((file) => file.size > limits.max_file_bytes);
    if (selected.some((file) => file.size > limits.max_file_bytes)) {
      queue.appendChild(h("p", { class: "upload-error" }, `Files must be ${formatBytes(limits.max_file_bytes)} or smaller. Oversized files are not uploaded.`));
    }
  };
  const addFiles = (files) => {
    const incoming = [...files];
    if (incoming.length + selected.length > 20) { toast("Select no more than 20 files at a time.", "error"); return; }
    for (const file of incoming) {
      if (file.name.length > limits.max_filename_length) { toast(`${file.name.slice(0, 40)}… has a filename longer than ${limits.max_filename_length} characters.`, "error"); continue; }
      if (selected.some((item) => item.name === file.name && item.size === file.size && item.lastModified === file.lastModified)) continue;
      selected.push(file);
    }
    paintQueue();
  };
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });
  dropzone.addEventListener("dragover", (event) => { event.preventDefault(); dropzone.classList.add("drag-active"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-active"));
  dropzone.addEventListener("drop", (event) => { event.preventDefault(); dropzone.classList.remove("drag-active"); addFiles(event.dataTransfer.files); });
  dropzone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInput.click(); } });
  dropzone.addEventListener("click", (event) => { if (event.target !== fileInput) fileInput.click(); });
  uploadButton.addEventListener("click", async () => {
    if (!selected.length || uploadButton.disabled) return;
    const batch = selected.slice();
    uploadButton.disabled = true;
    pickerButton.disabled = true;
    let succeeded = 0;
    const failures = [];
    const failedFiles = [];
    for (const file of batch) {
      const row = [...queue.children].find((item) => item.querySelector("strong")?.textContent === file.name);
      const status = h("span", { class: "upload-status" }, "Uploading…");
      if (row) row.appendChild(status);
      try {
        const item = await api.uploadEvidence(caseId, file, state.apiToken, (percent) => { status.textContent = `Uploading ${percent}%`; });
        status.textContent = `Stored · ${item.evidence_id}`;
        status.className = "upload-status success";
        succeeded++;
      } catch (error) {
        if (error.status === 403 && state.apiToken) state.apiToken = "";
        status.textContent = `Failed · ${error.message}`;
        status.className = "upload-status error";
        failures.push(`${file.name}: ${error.message}`);
        failedFiles.push(file);
      }
    }
    pickerButton.disabled = false;
    uploadButton.disabled = false;
    if (succeeded && !failures.length) {
      toast(`Uploaded ${succeeded} evidence file${succeeded === 1 ? "" : "s"}.`, "success");
      await renderInvestigationDetail(caseId, "evidence");
    } else if (succeeded) {
      toast(`${succeeded} uploaded; ${failures.length} failed. Failed files remain selected so you can retry.`, "error");
      selected = failedFiles;
      paintQueue();
      queue.appendChild(h("p", { class: "upload-error" }, failures.join(" · ")));
      const latest = await api.listEvidence(caseId);
      appendEvidenceTable(body, latest);
    } else {
      toast(`Upload failed: ${failures.join("; ")}`, "error");
    }
  });
  const uploadPanel = h("section", { class: "upload-panel card" }, [
    h("div", { class: "section-title" }, "Evidence intake"),
    h("p", { class: "section-sub" }, "Original files are copied into this investigation, hashed on the server, and kept unchanged for analysis."),
    dropzone, queue, h("div", { class: "upload-actions" }, [pickerButton, uploadButton, h("button", { class: "btn btn-ghost", onclick: () => openAddEvidenceModal(caseId) }, "Register server path")]),
  ]);
  body.appendChild(uploadPanel);
  if (list.length === 0) {
    body.appendChild(emptyState("▦", "No evidence yet", "Upload files from this device or register a file already accessible to the server."));
    return;
  }
  appendEvidenceTable(body, list);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function appendEvidenceTable(body, list) {
  const tableWrap = h("div", { class: "table-wrap" });
  const table = h("table", { class: "data-table" }, [
    h("thead", {}, h("tr", {}, ["ID", "Name", "Type", "Size", "SHA-256", "State"].map((t) => h("th", {}, t)))),
  ]);
  const tbody = h("tbody");
  list.forEach((e) => tbody.appendChild(h("tr", {}, [
    h("td", { class: "mono" }, e.evidence_id),
    h("td", { class: "evidence-name" }, e.original_name),
    h("td", { class: "mono" }, e.mime_type),
    h("td", {}, formatBytes(e.size_bytes)),
    h("td", { class: "mono hash-cell", title: e.sha256 }, e.sha256.slice(0, 16) + "…"),
    h("td", {}, badge(e.analysis_state, e.analysis_state)),
  ])));
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  body.appendChild(h("section", { class: "evidence-list" }, [h("div", { class: "section-title" }, `Evidence inventory · ${list.length}`), tableWrap]));
}

async function renderAnalysisTab(caseId, body) {
  const evidence = await api.listEvidence(caseId);
  if (evidence.length === 0) {
    body.appendChild(emptyState("▶", "No evidence to analyze", "Add evidence first."));
    return;
  }
  const evSelect = h("select", { id: "an-evidence" });
  evidence.forEach((e) => evSelect.appendChild(h("option", { value: e.evidence_id }, `${e.evidence_id} — ${e.original_name}`)));

  const runPanel = h("div", { class: "card" }, [
    h("div", { class: "section-title" }, "Run a tool"),
    h("div", { class: "field" }, [h("label", {}, "Evidence"), evSelect]),
    h("div", { class: "field" }, [h("label", {}, "Tool name"), h("input", { id: "an-tool", type: "text", placeholder: "e.g. file_identify, strings_extract, exif_metadata" })]),
    h("button", { class: "btn btn-primary", onclick: async () => {
      const ev = evSelect.value;
      const toolInput = document.getElementById("an-tool");
      const tool = toolInput.value.trim();
      if (!tool) { toast("Enter a tool name", "error"); return; }
      try {
        const result = await api.runAnalysis(caseId, ev, tool);
        toast(`Analysis ${result.status}`, result.ok ? "success" : "error");
        await renderInvestigationDetail(caseId, "analysis");
      } catch (err) { toast(err.message, "error"); }
    } }, "Run Analysis"),
  ]);
  body.appendChild(runPanel);

  body.appendChild(h("div", { class: "section-title" }, "Results"));
  const results = await api.listAnalysisResults(caseId);
  if (results.length === 0) {
    body.appendChild(emptyState("▶", "No analysis run yet", "Run a tool above against your evidence."));
    return;
  }
  results.forEach((r) => {
    body.appendChild(h("div", { class: "card" }, [
      h("div", { class: "list-item-title mono" }, `${r.id} — ${r.source_tool}`),
      h("div", { class: "list-item-sub" }, r.summary),
    ]));
  });
}

async function renderObservationsTab(caseId, body) {
  const list = await api.listObservations(caseId);
  if (list.length === 0) {
    body.appendChild(emptyState("◈", "No observations extracted yet", "Run analysis on evidence to extract indicators."));
    return;
  }
  const table = h("table", { class: "data-table" }, [h("thead", {}, h("tr", {}, ["ID", "Type", "Value", "Source"].map((t) => h("th", {}, t))))]);
  const tbody = h("tbody");
  list.forEach((o) => tbody.appendChild(h("tr", {}, [h("td", { class: "mono" }, o.observation_id), h("td", {}, badge(o.type, "info")), h("td", { class: "mono" }, o.value), h("td", { class: "mono" }, o.source_result_id)])));
  table.appendChild(tbody);
  body.appendChild(table);
}

async function renderCorrelationsTab(caseId, body) {
  const list = await api.listCorrelations(caseId);
  if (list.length === 0) {
    body.appendChild(emptyState("⬡", "No correlations identified yet", "Correlations appear automatically once two or more observations relate to each other."));
    return;
  }
  list.forEach((c) => {
    body.appendChild(h("div", { class: "card" }, [
      h("div", { class: "list-item-title" }, [badge(c.relationship, "info"), " ", c.correlation_id]),
      h("div", { class: "list-item-sub", style: "margin-top:6px" }, c.reasoning),
      h("div", { class: "finding-refs", style: "margin-top:6px" }, `entities: ${c.entity_ids.join(", ")}`),
    ]));
  });
}

async function renderFindingsTab(caseId, body) {
  const list = await api.listFindings(caseId);
  if (list.length === 0) {
    body.appendChild(emptyState("⚑", "No findings yet", "Run the AI Analyst to propose findings from collected evidence, or add one manually via the API."));
    return;
  }
  list.forEach((f) => body.appendChild(findingCard(caseId, f, true)));
}

function findingCard(caseId, f, withActions) {
  const card = h("div", { class: "finding-card" });
  card.appendChild(h("div", { class: "finding-title" }, [f.title, badge(f.severity, f.severity), badge(f.review_state, f.review_state)]));
  card.appendChild(h("div", { class: "finding-meta" }, `confidence ${(f.confidence * 100).toFixed(0)}% · ${f.finding_id}`));
  card.appendChild(h("div", { class: "finding-body" }, f.summary));
  card.appendChild(h("div", { class: "finding-body", style: "color:var(--text-2)" }, f.reasoning));
  card.appendChild(h("div", { class: "finding-refs" }, `refs: ${[...f.evidence_refs, ...f.tool_result_refs].join(", ") || "(none)"}`));
  if (f.analyst_note) card.appendChild(h("div", { class: "rejected-note" }, `Analyst note: ${f.analyst_note}`));
  if (withActions && f.review_state === "ai_proposed") {
    card.appendChild(
      h("div", { class: "finding-actions" }, [
        h("button", { class: "btn btn-sm btn-good", onclick: () => decide(caseId, f.finding_id, "confirm") }, "Confirm"),
        h("button", { class: "btn btn-sm btn-danger", onclick: () => decide(caseId, f.finding_id, "reject") }, "Reject"),
        h("button", { class: "btn btn-sm", onclick: () => decide(caseId, f.finding_id, "review") }, "Flag for Review"),
      ])
    );
  }
  return card;
}

async function decide(caseId, findingId, decision) {
  const note = decision !== "review" ? (window.prompt("Optional analyst note:") || undefined) : undefined;
  try {
    await api.decideFinding(caseId, findingId, decision, note);
    toast(`Finding ${findingId}: ${decision}`, "success");
    await renderInvestigationDetail(caseId, state.activeTab);
  } catch (err) {
    toast(err.message, "error");
  }
}

async function renderAiTab(caseId, body) {
  body.appendChild(
    h("div", { class: "analyst-panel" }, [
      h("div", { class: "analyst-header" }, ["✦ AI Analyst"]),
      h("div", { class: "analyst-status" }, "Interprets collected evidence and proposes findings. Every proposal must reference real evidence — fabricated references are rejected automatically, not silently accepted."),
      h("button", { class: "btn btn-primary", onclick: async (e) => {
        const btn = e.target;
        btn.disabled = true;
        btn.innerHTML = '<span class="inline-spinner"></span> Analyzing…';
        try {
          const result = await api.runAiAnalysis(caseId);
          toast(`${result.accepted.length} finding(s) proposed, ${result.rejected.length} rejected`, "success");
          await renderInvestigationDetail(caseId, "ai");
        } catch (err) {
          toast(err.message, "error");
          await renderInvestigationDetail(caseId, "ai");
        }
      } }, "Run AI Analysis"),
    ])
  );

  const findings = await api.listFindings(caseId);
  const proposed = findings.filter((f) => f.review_state === "ai_proposed" || f.review_state === "needs_review");
  body.appendChild(h("div", { class: "section-title" }, "Proposed Findings"));
  if (proposed.length === 0) {
    body.appendChild(emptyState("✦", "No AI-proposed findings", "Run AI Analysis above once evidence and observations exist."));
  } else {
    proposed.forEach((f) => body.appendChild(findingCard(caseId, f, true)));
  }
}

async function renderTimelineTab(caseId, body) {
  const events = await api.listTimeline(caseId);
  if (events.length === 0) {
    body.appendChild(emptyState("≡", "No timeline events yet", "Events appear as you add evidence and run analysis."));
    return;
  }
  events
    .slice()
    .sort((a, b) => a.timestamp - b.timestamp)
    .forEach((e) => {
      body.appendChild(
        h("div", { class: "list-item", style: "cursor:default" }, [
          h("div", { class: "list-item-main" }, [h("div", { class: "list-item-title mono" }, fmtTimeShort(e.timestamp)), h("div", { class: "list-item-sub" }, e.description)]),
          e.source_ref ? h("span", { class: "mono", style: "color:var(--text-2); font-size:11px" }, e.source_ref) : null,
        ])
      );
    });
}

async function renderReportTab(caseId, body) {
  const report = await api.getReportJson(caseId);
  const toolbar = h("div", { style: "margin-bottom:14px" }, [
    h("button", { class: "btn btn-sm", onclick: async () => {
      const md = await api.getReportMarkdown(caseId);
      const blob = new Blob([md], { type: "text/markdown" });
      const a = h("a", { href: URL.createObjectURL(blob), download: `${caseId}-report.md` });
      document.body.appendChild(a); a.click(); a.remove();
    } }, "Download Markdown"),
  ]);
  body.appendChild(toolbar);

  body.appendChild(
    h("div", { class: "report-section report-observed" }, [
      h("div", { class: "report-section-header" }, "▣ Observed"),
      h("div", {}, `${report.observed.evidence_inventory.length} evidence item(s), ${report.observed.observations.length} observation(s), ${report.observed.correlations.length} correlation(s).`),
    ])
  );

  const ai = report.ai_interpretation.proposed_findings.concat(report.ai_interpretation.needs_review_findings);
  body.appendChild(
    h("div", { class: "report-section report-ai" }, [
      h("div", { class: "report-section-header" }, "✦ AI Interpretation — not confirmed facts"),
      h("div", { class: "report-disclaimer" }, "These are AI-generated hypotheses awaiting human review."),
      ai.length ? h("div", {}, ai.map((f) => findingCard(caseId, f, false))) : h("div", { style: "color:var(--text-2)" }, "None."),
    ])
  );

  body.appendChild(
    h("div", { class: "report-section report-human" }, [
      h("div", { class: "report-section-header" }, "⚑ Human Decisions"),
      h("div", {}, `${report.human_decisions.confirmed_findings.length} confirmed, ${report.human_decisions.rejected_findings.length} rejected.`),
      report.human_decisions.confirmed_findings.length ? h("div", {}, report.human_decisions.confirmed_findings.map((f) => findingCard(caseId, f, false))) : null,
    ])
  );

  if (report.recommended_next_steps.length) {
    body.appendChild(h("div", { class: "report-section" }, [h("div", { class: "report-section-header" }, "→ Recommended Next Steps"), h("ul", {}, report.recommended_next_steps.map((s) => h("li", {}, s)))]));
  }
}

function openModal(contentEl) {
  const overlay = document.getElementById("modal-overlay");
  const panel = document.getElementById("modal-panel");
  panel.innerHTML = "";
  panel.appendChild(contentEl);
  overlay.hidden = false;
  overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };
}
function closeModal() {
  document.getElementById("modal-overlay").hidden = true;
}

function openNewInvestigationModal() {
  const nameInput = h("input", { type: "text", placeholder: "e.g. Suspicious email attachment" });
  const descInput = h("textarea", { rows: "3", placeholder: "Optional description" });
  openModal(
    h("div", {}, [
      h("h3", {}, "New Investigation"),
      h("div", { class: "field" }, [h("label", {}, "Name"), nameInput]),
      h("div", { class: "field" }, [h("label", {}, "Description"), descInput]),
      h("div", { class: "modal-actions" }, [
        h("button", { class: "btn", onclick: closeModal }, "Cancel"),
        h("button", { class: "btn btn-primary", onclick: async () => {
          if (!nameInput.value.trim()) { toast("Name is required", "error"); return; }
          try {
            const c = await api.createInvestigation(nameInput.value.trim(), descInput.value.trim());
            closeModal();
            toast(`Created ${c.case_id}`, "success");
            navigate(`#/investigations/${c.case_id}`);
          } catch (err) { toast(err.message, "error"); }
        } }, "Create"),
      ]),
    ])
  );
  setTimeout(() => nameInput.focus(), 50);
}

function openAddEvidenceModal(caseId) {
  const pathInput = h("input", { type: "text", placeholder: "/path/to/file (server-local path)" });
  openModal(
    h("div", {}, [
      h("h3", {}, "Add Evidence"),
      h("div", { class: "field" }, [
        h("label", {}, "File path available to the Cypher server"),
        pathInput,
      ]),
      h("div", { class: "section-sub" }, "Use this for files already stored on the server. To send a file from this device, use the upload area in Evidence Intake."),
      h("div", { class: "modal-actions" }, [
        h("button", { class: "btn", onclick: closeModal }, "Cancel"),
        h("button", { class: "btn btn-primary", onclick: async () => {
          if (!pathInput.value.trim()) { toast("Path is required", "error"); return; }
          try {
            const item = await api.addEvidence(caseId, pathInput.value.trim());
            closeModal();
            toast(`Registered ${item.evidence_id}`, "success");
            await renderInvestigationDetail(caseId, "evidence");
          } catch (err) { toast(err.message, "error"); }
        } }, "Add"),
      ]),
    ])
  );
  setTimeout(() => pathInput.focus(), 50);
}

const commands = [
  { label: "Create investigation", run: () => openNewInvestigationModal() },
  { label: "Go to dashboard", run: () => navigate("#/dashboard") },
  { label: "Go to investigations list", run: () => navigate("#/investigations") },
  { label: "Add evidence to current investigation", run: () => state.activeCaseId ? openAddEvidenceModal(state.activeCaseId) : toast("Open an investigation first", "error") },
  { label: "Run AI Analyst on current investigation", run: () => state.activeCaseId ? navigate(`#/investigations/${state.activeCaseId}/ai`) : toast("Open an investigation first", "error") },
  { label: "View findings", run: () => state.activeCaseId ? navigate(`#/investigations/${state.activeCaseId}/findings`) : toast("Open an investigation first", "error") },
  { label: "View timeline", run: () => state.activeCaseId ? navigate(`#/investigations/${state.activeCaseId}/timeline`) : toast("Open an investigation first", "error") },
  { label: "Generate report", run: () => state.activeCaseId ? navigate(`#/investigations/${state.activeCaseId}/report`) : toast("Open an investigation first", "error") },
];

function setupCommandPalette() {
  const overlay = document.getElementById("cmdk-overlay");
  const input = document.getElementById("cmdk-input");
  const results = document.getElementById("cmdk-results");
  let selected = 0;

  function renderResults(filter = "") {
    const filtered = commands.filter((c) => c.label.toLowerCase().includes(filter.toLowerCase()));
    results.innerHTML = "";
    filtered.forEach((c, i) => {
      results.appendChild(h("div", { class: `cmdk-item ${i === selected ? "selected" : ""}`, onclick: () => { c.run(); close(); } }, c.label));
    });
    return filtered;
  }

  function open() {
    overlay.hidden = false;
    input.value = "";
    selected = 0;
    renderResults();
    setTimeout(() => input.focus(), 30);
  }
  function close() {
    overlay.hidden = true;
  }

  document.getElementById("cmdk-btn").onclick = open;
  overlay.onclick = (e) => { if (e.target === overlay) close(); };
  input.oninput = () => { selected = 0; renderResults(input.value); };
  input.onkeydown = (e) => {
    const filtered = commands.filter((c) => c.label.toLowerCase().includes(input.value.toLowerCase()));
    if (e.key === "ArrowDown") { selected = Math.min(selected + 1, filtered.length - 1); renderResults(input.value); }
    else if (e.key === "ArrowUp") { selected = Math.max(selected - 1, 0); renderResults(input.value); }
    else if (e.key === "Enter" && filtered[selected]) { filtered[selected].run(); close(); }
    else if (e.key === "Escape") close();
  };

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); open(); }
    if (e.key === "Escape") { closeModal(); close(); }
  });
}

async function initializeApp() {
  try {
    const config = await api.getPublicConfig();
    state.publicDemo = config.public_demo === true;
  } catch {
    // Older/private backends keep their existing token behavior.
  }
  if (remoteApi && !state.publicDemo) {
    state.apiToken = window.prompt("Enter the Cypher access token configured by the server. It is kept only in this page until you close or reload it.") || "";
  }
  document.getElementById("new-investigation-btn").onclick = () => openNewInvestigationModal();
  document.querySelectorAll(".nav-item[data-route]").forEach((el) => {
    el.onclick = (e) => { e.preventDefault(); navigate(el.dataset.route); };
  });
  setupCommandPalette();
  window.addEventListener("hashchange", router);
  checkConnection();
  setInterval(checkConnection, 15000);
  router();
}

initializeApp();
