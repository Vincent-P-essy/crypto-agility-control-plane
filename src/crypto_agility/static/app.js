const byId = (id) => document.getElementById(id);

async function getJson(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function artifactButton(item, kind) {
  const button = document.createElement("button");
  button.className = "artifact";
  const title = document.createElement("span");
  title.textContent = kind === "cbom" ? `${item.summary?.finding_count ?? 0} findings` : item.environment?.openssl ?? "benchmark";
  const id = document.createElement("small");
  id.textContent = item.id;
  button.append(title, id);
  button.addEventListener("click", () => showArtifact(kind, item.id));
  return button;
}

async function refreshList(kind) {
  const target = byId(`${kind}s`);
  try {
    const items = await getJson(`/api/v1/${kind}s`);
    target.replaceChildren();
    if (!items.length) {
      target.textContent = `No stored ${kind} yet.`;
      target.className = "empty";
      return;
    }
    target.className = "";
    items.forEach((item) => target.append(artifactButton(item, kind)));
  } catch (error) {
    target.textContent = error.message;
  }
}

function metric(label, value) {
  const node = document.createElement("div");
  node.className = "metric";
  const name = document.createElement("span");
  name.textContent = label;
  const number = document.createElement("b");
  number.textContent = value;
  node.append(name, number);
  return node;
}

function showCbom(data) {
  const root = document.createElement("div");
  const metrics = document.createElement("div");
  metrics.className = "metric-grid";
  metrics.append(
    metric("Findings", data.summary.finding_count),
    metric("Critical", data.summary.severity_counts.critical),
    metric("High", data.summary.severity_counts.high),
    metric("HNDL flags", data.summary.hndl_relevant_count),
    metric("Actions", data.summary.migration_action_count),
  );
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Algorithm</th><th>Use</th><th>Exposure</th><th>Risk</th></tr></thead>";
  const body = document.createElement("tbody");
  const risks = new Map(data.assessments.map((entry) => [entry.finding_id, entry]));
  data.findings.slice(0, 30).forEach((finding) => {
    const risk = risks.get(finding.finding_id);
    const row = document.createElement("tr");
    [finding.algorithm, finding.use, finding.exposure, `${risk.score} ${risk.severity}`].forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 3) cell.className = risk.severity;
      row.append(cell);
    });
    body.append(row);
  });
  table.append(body);
  root.append(metrics, table);
  return root;
}

function showBenchmark(data) {
  const root = document.createElement("div");
  const metrics = document.createElement("div");
  metrics.className = "metric-grid";
  const classic = data.tls.find((item) => item.profile === "standard-tls-1.3");
  const hybrid = data.tls.find((item) => item.profile === "true-hybrid-tls-1.3");
  metrics.append(
    metric("Classic p50", `${classic.wall_latency.p50.toFixed(3)} ms`),
    metric("Hybrid p50", `${hybrid.wall_latency.p50.toFixed(3)} ms`),
    metric("Hybrid key share", `${hybrid.server_key_share_bytes} B`),
    metric("ML-KEM ct", `${data.application_pqc.sizes_bytes.kem_ciphertext} B`),
    metric("ML-DSA sig", `${data.application_pqc.sizes_bytes.signature} B`),
  );
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Operation</th><th>p50 wall</th><th>p95 wall</th><th>ops/s</th></tr></thead>";
  const body = document.createElement("tbody");
  data.application_pqc.operations.forEach((operation) => {
    const row = document.createElement("tr");
    [operation.operation, `${operation.wall_latency.p50.toFixed(3)} ms`, `${operation.wall_latency.p95.toFixed(3)} ms`, operation.throughput_operations_per_second.toFixed(1)].forEach((value) => {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    });
    body.append(row);
  });
  table.append(body);
  root.append(metrics, table);
  return root;
}

async function showArtifact(kind, id) {
  const detail = byId("detail");
  detail.textContent = "loading…";
  try {
    const data = await getJson(`/api/v1/${kind}s/${encodeURIComponent(id)}`);
    detail.replaceChildren(kind === "cbom" ? showCbom(data) : showBenchmark(data));
  } catch (error) {
    detail.textContent = error.message;
  }
}

async function boot() {
  try {
    const health = await getJson("/healthz");
    byId("health").textContent = `● ONLINE · registry ${health.registry_version}`;
    byId("health").className = "status ok";
  } catch (_) { byId("health").textContent = "● OFFLINE"; }
  await Promise.all([refreshList("cbom"), refreshList("benchmark")]);
}

byId("refresh-cboms").addEventListener("click", () => refreshList("cbom"));
byId("run-benchmark").addEventListener("click", async () => {
  const state = byId("benchmark-state");
  state.textContent = "Running real operations…";
  try {
    const report = await getJson("/api/v1/benchmarks", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({iterations: 25}),
    });
    state.textContent = "Measured successfully; no simulated fallback used.";
    await refreshList("benchmark");
    showArtifact("benchmark", report.report_id);
  } catch (error) { state.textContent = error.message; }
});
boot();
