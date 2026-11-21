(() => {
  "use strict";
  const page = document.body;
  const role = page.dataset.role;
  const csrfToken = page.dataset.csrfToken;
  const notice = document.querySelector("#notice");
  const statusNode = document.querySelector("#status");
  const operationNode = document.querySelector("#operation");
  const credentialMemory = new Map();
  const revealedCredentials = new Set();
  let status = null;
  let lease = null;
  let refreshTimer = null;
  let credentialClearTimer = null;
  let credentialRows = [];
  let credentialGeneration = null;

  const setNotice = (message, level = "") => { notice.textContent = message; notice.dataset.level = level; };
  const randomKey = () => crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
  const managementFetch = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    const payload = response.status === 204 ? null : await response.json();
    if (!response.ok) { throw new Error(payload && payload.message ? payload.message : "Management request failed."); }
    return { response, payload };
  };
  const mutation = (path, body, options = {}) => managementFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Management-Console": "1", "X-CSRF-Token": csrfToken, ...options.headers },
    body: JSON.stringify(body),
  });
  const clearCredentialMemory = () => {
    credentialMemory.clear();
    revealedCredentials.clear();
    credentialRows.forEach((credential) => {
      const token = tokenNode(credential.username);
      if (token) { token.textContent = "••••••••"; }
    });
    document.querySelectorAll("[data-reveal]").forEach((button) => { button.textContent = "Hiện"; });
    if (credentialClearTimer) { window.clearTimeout(credentialClearTimer); credentialClearTimer = null; }
  };
  const scheduleCredentialClear = () => {
    if (credentialClearTimer) { window.clearTimeout(credentialClearTimer); }
    credentialClearTimer = window.setTimeout(() => { clearCredentialMemory(); setNotice("Token tạm đã được xóa khỏi memory của tab.", ""); }, 60000);
  };
  const formatTime = (value) => value ? new Date(value * 1000).toLocaleString() : "—";
  const renderStatus = (value) => {
    status = value;
    statusNode.replaceChildren();
    const fields = [
      ["Lifecycle", value.lifecycle], ["Validated", String(value.validated)], ["State version", value.state_version],
      ["Credential generation", value.credential_generation], ["Active leases", value.evaluation_leases.active], ["Expired unreleased leases", value.evaluation_leases.expired_unreleased],
    ];
    fields.forEach(([label, item]) => { const dt = document.createElement("dt"); const dd = document.createElement("dd"); dt.textContent = label; dd.textContent = item; statusNode.append(dt, dd); });
    if (credentialGeneration !== null && credentialGeneration !== value.credential_generation) { clearCredentialMemory(); }
    credentialGeneration = value.credential_generation;
    const blockedByLease = value.evaluation_leases.active > 0 || value.evaluation_leases.expired_unreleased > 0;
    const start = document.querySelector('[data-lifecycle="start"]');
    if (start) { start.disabled = !["UNINITIALIZED", "READY"].includes(value.lifecycle) || blockedByLease; }
    const stop = document.querySelector('[data-lifecycle="stop"]');
    if (stop) { stop.disabled = value.lifecycle !== "RUNNING" || blockedByLease; }
    const reset = document.querySelector('[data-lifecycle="reset"]');
    if (reset) { reset.disabled = value.lifecycle !== "STOPPED" || blockedByLease; }
    const startForm = document.querySelector("#start-form");
    if (startForm) { startForm.hidden = !["UNINITIALIZED", "READY"].includes(value.lifecycle); }
    const resetForm = document.querySelector("#reset-form");
    if (resetForm) { resetForm.hidden = value.lifecycle !== "STOPPED"; }
    document.querySelectorAll("[data-reissue]").forEach((button) => { button.disabled = true; });
    if (value.lifecycle !== "RUNNING") { clearCredentialMemory(); }
  };
  const refreshStatus = async () => { const { payload } = await managementFetch("/management/v1/status"); renderStatus(payload); };
  const refreshLiveState = async () => { await Promise.all([refreshStatus(), refreshCredentials(), refreshCredentialAudit()]); };
  const renderOperation = (item) => { operationNode.textContent = `${item.operation_id}: ${item.state}${item.result_code ? ` (${item.result_code})` : ""}`; };
  const pollOperation = async (location) => {
    for (let wait = 500; wait <= 5000; wait = Math.min(wait * 2, 5000)) {
      const { payload } = await managementFetch(location);
      renderOperation(payload);
      if (payload.state !== "RUNNING") { await refreshStatus(); setNotice(`Operation ${payload.state}.`, payload.state === "SUCCEEDED" ? "success" : "error"); return; }
      await new Promise((resolve) => window.setTimeout(resolve, wait));
    }
  };
  const lifecycle = async (action, body) => {
    if (!status) { await refreshStatus(); }
    const { response, payload } = await mutation(`/management/v1/${action}`, body, { headers: { "Idempotency-Key": randomKey(), "If-Match": status.state_version } });
    renderOperation({ operation_id: payload.operation_id, state: "RUNNING" });
    await pollOperation(response.headers.get("Location"));
  };
  const populateScenarios = async () => {
    const { payload } = await managementFetch("/management/v1/scenarios");
    const list = document.querySelector("#scenarios");
    list.replaceChildren();
    payload.scenarios.forEach((scenario) => {
      const item = document.createElement("li"); item.textContent = `${scenario.code}: ${scenario.description}`; list.append(item);
    });
    document.querySelectorAll("#scenario, #reset-scenario").forEach((select) => {
      payload.scenarios.forEach((scenario) => { const option = document.createElement("option"); option.value = scenario.code; option.textContent = `${scenario.code} — ${scenario.description}`; select.append(option); });
    });
  };
  const tokenNode = (subject) => Array.from(document.querySelectorAll("[data-token]")).find((node) => node.dataset.token === subject);
  const renderCredentials = (credentials) => {
    credentialRows = credentials;
    const list = document.querySelector("#credential-list");
    if (!list) { return; }
    list.replaceChildren();
    credentials.forEach((credential) => {
      const row = document.createElement("tr");
      const token = document.createElement("td"); token.dataset.token = credential.username; token.textContent = revealedCredentials.has(credential.username) ? credentialMemory.get(credential.username) : "••••••••";
      [credential.username, credential.role, formatTime(credential.issued_at), formatTime(credential.expires_at), credential.status].forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); });
      row.append(token);
      const actions = document.createElement("td");
      const reveal = document.createElement("button"); reveal.type = "button"; reveal.dataset.reveal = credential.username; reveal.textContent = revealedCredentials.has(credential.username) ? "Ẩn" : "Hiện";
      reveal.disabled = credential.status !== "ACTIVE";
      reveal.addEventListener("click", () => revealCredential(credential.username).catch((error) => setNotice(error.message, "error")));
      const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "Sao chép"; copy.disabled = credential.status !== "ACTIVE";
      copy.addEventListener("click", () => copyCredential(credential.username).catch((error) => setNotice(error.message, "error")));
      actions.append(reveal, copy); row.append(actions); list.append(row);
    });
  };
  const refreshCredentials = async () => {
    const list = document.querySelector("#credential-list");
    if (!list) { return; }
    const { payload } = await managementFetch("/management/v1/credentials"); renderCredentials(payload.credentials);
  };
  const refreshCredentialAudit = async () => {
    const list = document.querySelector("#credential-audit");
    if (!list) { return; }
    const { payload } = await managementFetch("/management/v1/credentials/audit");
    list.replaceChildren();
    if (!payload.events.length) { const item = document.createElement("li"); item.textContent = "Chưa có thao tác token."; list.append(item); return; }
    payload.events.forEach((event) => { const item = document.createElement("li"); item.textContent = `${formatTime(event.created_at)} — ${event.actor}: ${event.action}${event.subject ? ` (${event.subject})` : ""} — ${event.result_code}`; list.append(item); });
  };
  const rememberCredential = (credential) => { credentialMemory.set(credential.username, credential.token); scheduleCredentialClear(); };
  const revealCredential = async (subject) => {
    const token = tokenNode(subject);
    const reveal = document.querySelector(`[data-reveal="${subject}"]`);
    if (revealedCredentials.has(subject)) {
      revealedCredentials.delete(subject);
      if (token) { token.textContent = "••••••••"; }
      if (reveal) { reveal.textContent = "Hiện"; }
      return;
    }
    if (!credentialMemory.has(subject)) {
      const { payload } = await mutation(`/management/v1/credentials/${encodeURIComponent(subject)}/reveal`, {});
      rememberCredential(payload.credential);
    }
    revealedCredentials.add(subject);
    if (token) { token.textContent = credentialMemory.get(subject); }
    if (reveal) { reveal.textContent = "Ẩn"; }
    await refreshCredentialAudit();
  };
  const copyToken = async (token) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(token);
      return;
    }
    throw new Error("Trình duyệt không cho sao chép tự động. Hãy bấm Hiện rồi sao chép token thủ công.");
  };
  const copyCredential = async (subject) => {
    if (!credentialMemory.has(subject)) { await revealCredential(subject); }
    await copyToken(credentialMemory.get(subject));
    await mutation(`/management/v1/credentials/${encodeURIComponent(subject)}/copy-audit`, {});
    setNotice("Đã sao chép token. Hãy xóa clipboard sau khi hoàn tất.", "success"); await refreshCredentialAudit();
  };
  const lifecycleFailure = (error) => { setNotice(error.message, "error"); refreshLiveState().catch(() => {}); };
  const startForm = document.querySelector("#start-form");
  if (startForm) { startForm.addEventListener("submit", (event) => { event.preventDefault(); const body = status && status.lifecycle === "READY" ? {} : { scenario: document.querySelector("#scenario").value, token_ttl_seconds: Number(document.querySelector("#token-ttl").value) }; lifecycle("start", body).then(refreshLiveState).catch(lifecycleFailure); }); }
  const stop = document.querySelector('[data-lifecycle="stop"]');
  if (stop) { stop.addEventListener("click", () => lifecycle("stop", {}).then(() => { clearCredentialMemory(); return refreshLiveState(); }).catch(lifecycleFailure)); }
  const resetForm = document.querySelector("#reset-form");
  if (resetForm) { resetForm.addEventListener("submit", (event) => { event.preventDefault(); lifecycle("reset", { scenario: document.querySelector("#reset-scenario").value, token_ttl_seconds: Number(document.querySelector("#reset-token-ttl").value), confirm_invalidate_tokens: true }).then(() => { clearCredentialMemory(); return refreshLiveState(); }).catch(lifecycleFailure); }); }
  const leaseForm = document.querySelector("#lease-form");
  if (leaseForm) { leaseForm.addEventListener("submit", async (event) => { event.preventDefault(); try { const { payload } = await mutation("/management/v1/evaluation-leases", { duration_seconds: Number(document.querySelector("#lease-duration").value) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; document.querySelector("#renew-lease").disabled = false; document.querySelector("#release-lease").disabled = false; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const renew = document.querySelector("#renew-lease");
  if (renew) { renew.addEventListener("click", async () => { if (!lease) return; try { const { payload } = await mutation(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}/renew`, { duration_seconds: Number(document.querySelector("#lease-duration").value) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const release = document.querySelector("#release-lease");
  if (release) { release.addEventListener("click", async () => { if (!lease) return; try { await managementFetch(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}`, { method: "DELETE", headers: { "X-Management-Console": "1", "X-CSRF-Token": csrfToken } }); lease = null; document.querySelector("#lease").textContent = "Lease released."; renew.disabled = true; release.disabled = true; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const boot = async () => { try { await Promise.all([refreshLiveState(), populateScenarios()]); setNotice("Management console ready.", "success"); } catch (error) { setNotice(error.message, "error"); } };
  boot();
  document.addEventListener("visibilitychange", () => { if (document.hidden) { window.clearInterval(refreshTimer); refreshTimer = null; } else if (!refreshTimer) { refreshLiveState().catch(() => {}); refreshTimer = window.setInterval(() => refreshLiveState().catch(() => {}), 10000); } });
  window.addEventListener("pagehide", clearCredentialMemory);
  refreshTimer = window.setInterval(() => refreshLiveState().catch(() => {}), 10000);
})();
