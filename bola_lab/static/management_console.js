(() => {
  "use strict";
  const page = document.body;
  const role = page.dataset.role;
  const csrfToken = page.dataset.csrfToken;
  const notice = document.querySelector("#notice");
  const statusNode = document.querySelector("#status");
  const operationNode = document.querySelector("#operation");
  let status = null;
  let lease = null;
  let refreshTimer = null;

  const setNotice = (message, level = "") => { notice.textContent = message; notice.dataset.level = level; };
  const randomKey = () => crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "");
  const managementFetch = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    const payload = response.status === 204 ? null : await response.json();
    if (!response.ok) { throw new Error(payload && payload.message ? payload.message : "Management request failed."); }
    return { response, payload };
  };
  const renderStatus = (value) => {
    status = value;
    statusNode.replaceChildren();
    const fields = [
      ["Lifecycle", value.lifecycle], ["Validated", String(value.validated)], ["State version", value.state_version],
      ["Token expiry", value.token_expires_at || "n/a"], ["Credential generation", value.credential_generation],
      ["Active leases", value.evaluation_leases.active], ["Expired unreleased leases", value.evaluation_leases.expired_unreleased],
    ];
    fields.forEach(([label, item]) => { const dt = document.createElement("dt"); const dd = document.createElement("dd"); dt.textContent = label; dd.textContent = item; statusNode.append(dt, dd); });
    document.querySelectorAll("[data-lifecycle]").forEach((button) => { button.disabled = value.lifecycle === "UNKNOWN"; });
    const stop = document.querySelector('[data-lifecycle="stop"]');
    if (stop) { stop.disabled = value.lifecycle === "UNKNOWN" || value.evaluation_leases.active > 0 || value.evaluation_leases.expired_unreleased > 0; }
    const reset = document.querySelector("#reset-form button");
    if (reset) { reset.disabled = value.lifecycle !== "STOPPED" || value.evaluation_leases.active > 0 || value.evaluation_leases.expired_unreleased > 0; }
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
    const key = randomKey();
    const { response, payload } = await managementFetch(`/management/v1/${action}`, {
      method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": key, "If-Match": status.state_version, "X-Management-Console": "1", "X-CSRF-Token": csrfToken }, body: JSON.stringify(body),
    });
    renderOperation({ operation_id: payload.operation_id, state: "RUNNING" });
    await pollOperation(response.headers.get("Location"));
  };
  const populateScenarios = async () => {
    const { payload } = await managementFetch("/management/v1/scenarios");
    const list = document.querySelector("#scenarios");
    list.replaceChildren();
    payload.scenarios.forEach((scenario) => {
      const item = document.createElement("li");
      item.textContent = `${scenario.code}: ${scenario.description}`;
      list.append(item);
    });
    document.querySelectorAll("#scenario, #reset-scenario").forEach((select) => {
      payload.scenarios.forEach((scenario) => {
        const option = document.createElement("option");
        option.value = scenario.code;
        option.textContent = `${scenario.code} — ${scenario.description}`;
        select.append(option);
      });
    });
  };
  document.querySelectorAll("[data-lifecycle]").forEach((button) => button.addEventListener("click", () => lifecycle(button.dataset.lifecycle, {}).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); })));
  const initForm = document.querySelector("#init-form");
  if (initForm) { initForm.addEventListener("submit", (event) => { event.preventDefault(); lifecycle("init", { scenario: document.querySelector("#scenario").value, token_ttl_seconds: Number(document.querySelector("#token-ttl").value) }).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); }); }); }
  const resetForm = document.querySelector("#reset-form");
  if (resetForm) { resetForm.addEventListener("submit", (event) => { event.preventDefault(); lifecycle("reset", { scenario: document.querySelector("#reset-scenario").value, token_ttl_seconds: Number(document.querySelector("#reset-token-ttl").value), confirm_invalidate_tokens: true }).catch((error) => { setNotice(error.message, "error"); refreshStatus().catch(() => {}); }); }); }
  const leaseForm = document.querySelector("#lease-form");
  if (leaseForm) { leaseForm.addEventListener("submit", async (event) => { event.preventDefault(); try { const { payload } = await managementFetch("/management/v1/evaluation-leases", { method: "POST", headers: { "Content-Type": "application/json", "X-Management-Console": "1", "X-CSRF-Token": csrfToken }, body: JSON.stringify({ duration_seconds: Number(document.querySelector("#lease-duration").value) }) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; document.querySelector("#renew-lease").disabled = false; document.querySelector("#release-lease").disabled = false; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const renew = document.querySelector("#renew-lease");
  if (renew) { renew.addEventListener("click", async () => { if (!lease) return; try { const { payload } = await managementFetch(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}/renew`, { method: "POST", headers: { "Content-Type": "application/json", "X-Management-Console": "1", "X-CSRF-Token": csrfToken }, body: JSON.stringify({ duration_seconds: Number(document.querySelector("#lease-duration").value) }) }); lease = payload; document.querySelector("#lease").textContent = `Lease expires at ${payload.expires_at}.`; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const release = document.querySelector("#release-lease");
  if (release) { release.addEventListener("click", async () => { if (!lease) return; try { await managementFetch(`/management/v1/evaluation-leases/${encodeURIComponent(lease.lease_id)}`, { method: "DELETE", headers: { "X-Management-Console": "1", "X-CSRF-Token": csrfToken } }); lease = null; document.querySelector("#lease").textContent = "Lease released."; renew.disabled = true; release.disabled = true; await refreshStatus(); } catch (error) { setNotice(error.message, "error"); } }); }
  const boot = async () => { try { await Promise.all([refreshStatus(), populateScenarios()]); setNotice("Management console ready.", "success"); } catch (error) { setNotice(error.message, "error"); } };
  boot();
  document.addEventListener("visibilitychange", () => { if (document.hidden) { window.clearInterval(refreshTimer); refreshTimer = null; } else if (!refreshTimer) { refreshStatus().catch(() => {}); refreshTimer = window.setInterval(() => refreshStatus().catch(() => {}), 10000); } });
  refreshTimer = window.setInterval(() => refreshStatus().catch(() => {}), 10000);
})();
