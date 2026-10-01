// Integration check: drives the ACTUAL frontend API client (frontend/api.js)
// against a REAL running Cypher backend, using Node's native fetch. This is
// not a browser test (no DOM/rendering is exercised), but it does prove the
// frontend's data layer and the backend's real HTTP responses genuinely
// agree on shape and behavior -- not just "the JS parses".
import { createClient } from "../frontend/api.js";

const base = process.argv[2];
if (!base) {
  console.error("usage: node verify_frontend_api.mjs <base_url>");
  process.exit(2);
}
const api = createClient(base);

let failures = 0;
function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`PASS: ${msg}`);
  }
}

const investigations = await api.listInvestigations();
assert(Array.isArray(investigations), "listInvestigations returns an array");

const created = await api.createInvestigation("Node integration check", "created by verify_frontend_api.mjs");
assert(created.case_id && created.case_id.startsWith("CASE-"), "createInvestigation returns a valid case_id");
assert(created.status === "open", "new investigation starts 'open'");

const fetched = await api.getInvestigation(created.case_id);
assert(fetched.name === "Node integration check", "getInvestigation round-trips the name");

const evidenceList = await api.listEvidence(created.case_id);
assert(Array.isArray(evidenceList) && evidenceList.length === 0, "listEvidence is empty for a fresh case");

const fs = await import("node:fs");
const os = await import("node:os");
const path = await import("node:path");
const tmpFile = path.join(os.tmpdir(), "cypher-frontend-verify-sample.txt");
fs.writeFileSync(tmpFile, "contains an ip 10.1.2.3 and a domain example.com");
let ev;
try {
  ev = await api.addEvidence(created.case_id, tmpFile);
} finally {
  fs.rmSync(tmpFile, { force: true });
}
assert(ev.evidence_id === "EVID-0001", "addEvidence assigns EVID-0001");

const analysisResult = await api.runAnalysis(created.case_id, "EVID-0001", "strings_extract");
assert(analysisResult.status === "COMPLETED", "runAnalysis completes successfully");

const observations = await api.listObservations(created.case_id);
assert(observations.some((o) => o.value === "10.1.2.3"), "observation extraction found the IP");
assert(observations.some((o) => o.value === "example.com"), "observation extraction found the domain");

const correlations = await api.listCorrelations(created.case_id);
assert(correlations.some((c) => c.relationship === "co_occurring"), "co-occurrence correlation was created");

const timeline = await api.listTimeline(created.case_id);
assert(timeline.length >= 2, "timeline has real events (evidence + analysis)");

const report = await api.getReportJson(created.case_id);
assert(report.observed.evidence_inventory.length === 1, "report reflects the real evidence count");
assert(Array.isArray(report.ai_interpretation.proposed_findings), "report has the ai_interpretation section");

const md = await api.getReportMarkdown(created.case_id);
assert(typeof md === "string" && md.includes("Investigation Report"), "markdown report renders");

// Error handling: a well-formed but nonexistent ID must come back as a
// clean 404. A malformed ID must come back as a 400. Neither should
// ever surface as an uncaught network-level error.
try {
  await api.getInvestigation("CASE-deadbeef");
  console.error("FAIL: expected getInvestigation on a well-formed-but-missing ID to throw");
  failures++;
} catch (err) {
  assert(err.status === 404, `well-formed nonexistent case ID returns 404 (got ${err.status})`);
}

try {
  await api.getInvestigation("CASE-not-valid-format");
  console.error("FAIL: expected getInvestigation on a malformed ID to throw");
  failures++;
} catch (err) {
  assert(err.status === 400, `malformed case ID returns 400 (got ${err.status})`);
}

console.log(`\n${failures === 0 ? "ALL PASSED" : failures + " FAILURE(S)"}`);
process.exit(failures === 0 ? 0 : 1);
