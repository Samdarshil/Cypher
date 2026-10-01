// Cypher API client. Pure fetch wrappers, no DOM — kept separate from
// app.js specifically so this module can be exercised from Node (see
// scripts/verify_frontend_api.mjs) against a REAL running backend
// without needing a browser.

export class ApiError extends Error {
  constructor(status, payload) {
    super((payload && payload.error) || `HTTP ${status}`);
    this.status = status;
    this.payload = payload;
  }
}

export function createClient(base, getToken = () => "") {
  async function request(method, path, body) {
    const opts = { method, headers: {} };
    const token = getToken();
    if (token) opts.headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(base + path, opts);
    const ctype = res.headers.get("Content-Type") || "";
    const isJson = ctype.includes("application/json");
    const payload = isJson ? await res.json().catch(() => null) : await res.text();
    if (!res.ok) throw new ApiError(res.status, payload);
    return payload;
  }

  return {
    getPublicConfig: () => request("GET", "/public-config"),
    listInvestigations: () => request("GET", "/investigations"),
    getUploadLimits: () => request("GET", "/upload-limits"),
    createInvestigation: (name, description) =>
      request("POST", "/investigations", { name, description }),
    getInvestigation: (id) => request("GET", `/investigations/${id}`),

    listEvidence: (id) => request("GET", `/investigations/${id}/evidence`),
    addEvidence: (id, path) => request("POST", `/investigations/${id}/evidence`, { path }),
    uploadEvidence: (id, file, token = "", onProgress = () => {}) => new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${base}/investigations/${id}/evidence/upload`);
      if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
      };
      xhr.onerror = () => reject(new Error("Network error while uploading evidence."));
      xhr.onload = () => {
        const payload = (() => { try { return JSON.parse(xhr.responseText); } catch { return {}; } })();
        if (xhr.status < 200 || xhr.status >= 300) {
          reject(new ApiError(xhr.status, payload));
          return;
        }
        resolve(payload);
      };
      const data = new FormData();
      data.append("file", file, file.name);
      xhr.send(data);
    }),

    runAnalysis: (id, evidenceId, tool) =>
      request("POST", `/investigations/${id}/analysis`, { evidence_id: evidenceId, tool }),
    listAnalysisResults: (id) => request("GET", `/investigations/${id}/analysis`),

    listObservations: (id) => request("GET", `/investigations/${id}/observations`),
    listEntities: (id) => request("GET", `/investigations/${id}/entities`),
    listCorrelations: (id) => request("GET", `/investigations/${id}/correlations`),

    listFindings: (id) => request("GET", `/investigations/${id}/findings`),
    runAiAnalysis: (id) => request("POST", `/investigations/${id}/ai-analysis`),
    decideFinding: (id, findingId, decision, note) =>
      request("POST", `/investigations/${id}/findings/${findingId}/decision`, { decision, note }),

    listTimeline: (id) => request("GET", `/investigations/${id}/timeline`),
    getReportJson: (id) => request("GET", `/investigations/${id}/report?format=json`),
    getReportMarkdown: (id) => request("GET", `/investigations/${id}/report?format=markdown`),
  };
}
