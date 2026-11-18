(() => {
  "use strict";
  const page = document.body;
  const role = page.dataset.role;
  const csrfToken = page.dataset.csrfToken;
  const notice = document.querySelector("#notice");
  const statusNode = document.querySelector("#status");
  const operationNode = document.querySelector("#operation");
  const credentialMemory = new Map();
  let status = null;
  let lease = null;
  let refreshTimer = null;
  let credentialClearTimer = null;

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
    document.querySelectorAll("[data-token]").forEach((node) => { node.textContent = "••••••••"; });
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
    document.querySelectorAll("[data-lifecycle]").forEach((button) => { button.disabled = value.lifecycle === "UNKNOWN"; });
    const stop = document.querySelector('[data-lifecycle="stop"]');
    if (stop) { stop.disabled = value.lifecycle === "UNKNOWN" || value.evaluation_leases.active > 0 || value.evaluation_leases.expired_unreleased > 0; }
    const reset = document.querySelector("#reset-form button");
    if (reset) { reset.disabled = value.lifecycle !== "STOPPED" || value.evaluation_leases.active > 0 || value.evaluation_leases.expired_unreleased > 0; }
    const issue = document.querySelector("#credential-issue");
    if (issue) { issue.disabled = value.lifecycle === "UNKNOWN"; }
    document.querySelectorAll("[data-reissue]").forEach((button) => { button.disabled = value.lifecycle === "UNKNOWN" || button.dataset.eligible !== "true"; });
  };
  const refreshStatus = async () => { const { payload } = await managementFetch("/management/v1/status"); renderStatus(payload); };
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
  const renderCredentials = (credentials) => {
    const list = document.querySelector("#credential-list");
    if (!list) { return; }
    list.replaceChildren();
    credentials.forEach((credential) => {
      const row = document.createElement("tr");
      const token = document.createElement("td"); token.dataset.token = credential.username; token.textContent = "••••••••";
      [credential.username, credential.role, formatTime(credential.issued_at), formatTime(credential.expires_at), credential.status].forEach((value) => { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); });
      row.append(token);
      const actions = document.createElement("td");
      const reveal = document.createElement("button"); reveal.type = "button"; reveal.textContent = credentialMemory.has(credential.username) ? "Ẩn" : "Hiện";
      reveal.disabled = credential.status !== "ACTIVE";
      reveal.addEventListener("click", () => revealCredential(credential.username).catch((error) => setNotice(error.message, "error")));
      const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "Sao chép"; copy.disabled = credential.status !== "ACTIVE";
      copy.addEventListener("click", () => copyCredential(credential.username).catch((error) => setNotice(error.message, "error")));
      const reissue = document.createElement("button"); reissue.type = "button"; reissue.textContent = "Cấp lại"; reissue.dataset.reissue = credential.username; reissue.dataset.eligible = String(["EXPIRED", "REVOKED"].includes(credential.status)); reissue.disabled = reissue.dataset.eligible !== "true" || (status && status.lifecycle === "UNKNOWN");
      reissue.addEventListener("click", () => reissueCredential(credential.username).catch((error) => setNotice(error.message, "error")));
      actions.append(reveal, copy, reissue); row.append(actions); list.append(row);
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
    if (credentialMemory.has(subject)) { credentialMemory.delete(subject); await refreshCredentials(); return; }
    const { payload } = await mutation(`/management/v1/credentials/${encodeURIComponent(subject)}/reveal`, {});
    rememberCredential(payload.credential); await refreshCredentials();
    const node = document.querySelector(`[data-token="${CSS.escape(subject)}"]`); if (node) { node.textContent = payload.credential.token; }
    await refreshCredentialAudit();
  };
  const copyCredential = async (subject) => {
    if (!credentialMemory.has(subject)) { await revealCredential(subject); }
    await navigator.clipboard.writeText(credentialMemory.get(subject));
    await mutation(`/management/v1/credentials/${encodeURIComponent(subject)}/copy-audit`, {});
    setNotice("Đã sao chép token. Hãy xóa clipboard sau khi hoàn tất.", "success"); await refreshCredentialAudit();
  };
  const issueCredentials = async () => {
    if (!status) { await refreshStatus(); }
    const ttl = Number(document.querySelector("#credential-ttl").value);
    const { payload } = await mutation("/management/v1/credentials/issue", { token_ttl_seconds: ttl }, { headers: { "Idempotency-Key": randomKey(), "If-Match": status.state_version } });
    payload.credentials.forEach(rememberCredential); await Promise.all([refreshCredentials(), refreshCredentialAudit(), refreshStatus()]);
    setNotice("Đã cấp token cho admin, userA và userB. Giá trị đang được che.", "success");
  };
  const reissueCredential = async (subject) => {
    if (!status) { await refreshStatus(); }
    const ttl = Number(document.querySelector("#credential-ttl").value);
    const { payload } = await mutation(`/management/v1/credentials/${encodeURIComponent(subject)}/reissue`, { token_ttl_seconds: ttl, confirm_invalidate_previous: true }, { headers: { "Idempotency-Key": randomKey(), "If-Match": status.state_version } });
    credentialMemory.delete(subject); rememberCredential(payload.credential); await Promise.all([refreshCredentials(), refreshCredentialAudit(), refreshStatus()]);
    setNotice(`Đã cấp lại token ${subject}; token trước đó đã không còn hiệu lực.`, "success");
  };
  const revokeCredentials = async () => {
    if (!status) { await refreshStatus(); }
    await mutation("/management/v1/credentials/revoke-all", { confirm_revoke_all: true }, { headers: { "Idempotency-Key": randomKey(), "If-Match": status.state_version } });
    clearCredentialMemory(); await Promise.all([refreshCredentials(), refreshCredentialAudit(), refreshStatus()]);
    setNotice("Đã thu hồi toàn bộ token hiện tại.", "success");
  };
  document.querySelectorAll("[data-lifecycle]").forEach((button) => button.addEventListener("click", () => lifecycle(button.dataset.lifecycle, {}).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); })));
  const initForm = document.querySelector("#init-form");
  if (initForm) { initForm.addEventListener("submit", (event) => { event.preventDefault(); lifecycle("init", { scenario: document.querySelector("#scenario").value, token_ttl_seconds: Number(document.querySelector("#token-ttl").value) }).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); }); }); }
  const resetForm = document.querySelector("#reset-form");
  if (resetForm) { resetForm.addEventListener("submit", (event) => { event.preventDefault(); clearCredentialMemory(); lifecycle("reset", { scenario: document.querySelector("#reset-scenario").value, token_ttl_seconds: Number(document.querySelector("#reset-token-ttl").value), confirm_invalidate_tokens: true }).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); }); }); }
  const issueForm = document.querySelector("#credential-issue-form");
  if (issueForm) { issueForm.addEventListener("submit", (event) => { event.preventDefault(); issueCredentials().catch((error) => { setNotice(error.message, "error"); refreshCredentials().catch(() => {}); }); }); }
  const revokeForm = document.querySelector("#credential-revoke-form");
  if (revokeForm) { revokeForm.addEventListener("submit", (event) => { event.preventDefault(); revokeCredentials().catch((error) => setNotice(error.message, "error")); }); }
  const leaseForm = document.querySelector("#lease-form");
  if (leaseForm) { leaseForm.addEventListener("submit", async (event) => { event.preventDefault(); try { const { payload } = await mutation("/management/v1/evaluation-leases", { duration_seconds: Number(document.querySelector("#lease-duration").value) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; document.querySelector("#renew-lease").disabled = false; document.querySelector("#release-lease").disabled = false; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const renew = document.querySelector("#renew-lease");
  if (renew) { renew.addEventListener("click", async () => { if (!lease) return; try { const { payload } = await mutation(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}/renew`, { duration_seconds: Number(document.querySelector("#lease-duration").value) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const release = document.querySelector("#release-lease");
  if (release) { release.addEventListener("click", async () => { if (!lease) return; try { await managementFetch(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}`, { method: "DELETE", headers: { "X-Management-Console": "1", "X-CSRF-Token": csrfToken } }); lease = null; document.querySelector("#lease").textContent = "Lease released."; renew.disabled = true; release.disabled = true; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const boot = async () => { try { await Promise.all([refreshStatus(), populateScenarios(), refreshCredentials(), refreshCredentialAudit()]); setNotice("Management console ready.", "success"); } catch (error) { setNotice(error.message, "error"); } };
  boot();
  document.addEventListener("visibilitychange", () => { if (document.hidden) { window.clearInterval(refreshTimer); refreshTimer = null; } else if (!refreshTimer) { refreshStatus().catch(() => {}); refreshTimer = window.setInterval(() => refreshStatus().catch(() => {}), 10000); } });
  window.addEventListener("pagehide", clearCredentialMemory);
  refreshTimer = window.setInterval(() => refreshStatus().catch(() => {}), 10000);
})();
