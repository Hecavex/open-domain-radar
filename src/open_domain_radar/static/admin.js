(() => {
  "use strict";

  const API_ROOT = "/api/admin/v1";
  const PUBLIC_API_ROOT = "/api/public/v1";
  const state = {
    csrf: "",
    session: null,
    targets: [],
    providers: [],
    candidates: [],
    pivots: [],
    runs: [],
    suppressions: [],
    selectedCandidate: null,
    candidatePage: 1,
    candidatePages: 1,
    candidateTotal: 0,
  };
  const byId = (id) => document.getElementById(id);

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function list(value) {
    if (Array.isArray(value)) return value.filter((item) => item !== null && item !== undefined);
    if (value === null || value === undefined || value === "") return [];
    if (typeof value === "object") return Object.entries(value).map(([name, record]) => ({ name, ...(typeof record === "object" ? record : { value: record }) }));
    return [value];
  }

  function first(object, keys, fallback = "—") {
    for (const key of keys) {
      if (object && object[key] !== undefined && object[key] !== null && object[key] !== "") return object[key];
    }
    return fallback;
  }

  function slug(value) {
    return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  }

  function defang(value) {
    return String(value || "unknown").trim().replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:").replace(/\[\.\]/g, "\u0000").replace(/\./g, "[.]").replace(/\u0000/g, "[.]");
  }

  function formatDate(value, includeTime = true) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return String(value);
    const preference = localStorage.getItem("odr-time") || "local";
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      ...(includeTime ? { timeStyle: "short" } : {}),
      ...(preference === "utc" ? { timeZone: "UTC", timeZoneName: "short" } : {}),
    }).format(date);
  }

  function lines(value) {
    if (Array.isArray(value)) return value.filter(Boolean);
    return String(value || "").split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
  }

  function candidatePageSize() {
    const value = Number(localStorage.getItem("odr-page-size") || 25);
    return [10, 25, 50].includes(value) ? value : 25;
  }

  function signalDomain(signal) {
    return first(signal, ["defanged", "observable", "indicator", "domain", "hostname", "url"], "unknown");
  }

  function targetName(signal) {
    const target = first(signal, ["target", "target_name", "brand", "watch_target"], "Unspecified");
    return typeof target === "object" ? first(target, ["name", "label"], "Unspecified") : target;
  }

  function scoreValue(signal) {
    const raw = Number(first(signal, ["confidence", "score", "confidence_score", "risk_score"], 0));
    if (Number.isNaN(raw)) return 0;
    return raw <= 1 && raw > 0 ? Math.round(raw * 100) : Math.round(raw);
  }

  function scoreClass(score) {
    if (score >= 75) return "score score--high";
    if (score >= 45) return "score score--medium";
    return "score";
  }

  function statusBadge(value) {
    const status = String(value || "unknown").replaceAll("_", " ");
    return element("span", `status-badge status-${slug(status)}`, status);
  }

  async function request(path, options = {}) {
    const mutation = options.method && options.method !== "GET";
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (mutation && options.body !== undefined) headers["Content-Type"] = "application/json";
    if (mutation && state.csrf) headers["X-CSRF-Token"] = state.csrf;
    const response = await fetch(`${API_ROOT}${path}`, {
      credentials: "same-origin",
      ...options,
      headers,
      body: options.body !== undefined && typeof options.body !== "string" ? JSON.stringify(options.body) : options.body,
    });
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try {
        const payload = await response.json();
        message = payload.detail || payload.message || payload.error || message;
      } catch (_) {
        // Preserve a useful HTTP status if a reverse proxy returns HTML.
      }
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    if (response.status === 204) return {};
    return response.json();
  }

  async function publicRequest(path) {
    const response = await fetch(`${PUBLIC_API_ROOT}${path}`, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Public API request failed (${response.status})`);
    return response.json();
  }

  function setView(view) {
    for (const id of ["auth-loading", "setup-view", "login-view", "workspace"]) byId(id).hidden = id !== view;
    byId("logout-button").hidden = view !== "workspace";
  }

  function setFormMessage(id, message = "", success = false) {
    const node = byId(id);
    node.textContent = message;
    node.className = `form-message${success ? " is-success" : ""}`;
  }

  let alertTimer = 0;
  function alertMessage(message, mode = "success") {
    const node = byId("admin-alert");
    node.textContent = message;
    node.className = `admin-alert is-${mode}`;
    node.hidden = false;
    clearTimeout(alertTimer);
    alertTimer = window.setTimeout(() => { node.hidden = true; }, 6500);
  }

  async function bootstrap() {
    setView("auth-loading");
    try {
      const session = await request("/session");
      state.session = session;
      state.csrf = String(first(session, ["csrf_token", "csrf"], ""));
      if (session.setup_required === true || session.initialized === false || session.has_operator === false) {
        setView("setup-view");
        byId("setup-recheck").focus();
        return;
      }
      if (session.authenticated === true || session.logged_in === true || session.user || session.username) {
        openWorkspace(session);
        return;
      }
      setView("login-view");
      byId("login-username").focus();
    } catch (error) {
      if (error.status === 401 || error.status === 403) {
        setView("login-view");
        byId("login-username").focus();
      } else {
        setView("login-view");
        setFormMessage("login-message", `${error.message}. Confirm that the local API is running.`);
      }
    }
  }

  async function openWorkspace(session) {
    setView("workspace");
    const user = session.user || {};
    byId("operator-name").textContent = typeof user === "string" ? user : first(user, ["display_name", "username", "name"], first(session, ["username"], "Operator"));
    const requested = location.hash.replace("#", "");
    showSection(["overview", "targets", "integrations", "review", "pivots", "settings"].includes(requested) ? requested : "overview", false);
    await refreshWorkspace();
  }

  async function refreshWorkspace() {
    const targetResult = await Promise.allSettled([loadTargets()]);
    const results = targetResult.concat(await Promise.allSettled([loadProviders(), loadCandidates(), loadPivots(), loadRuns(), loadSuppressions(), loadHealth(), loadPublicStats()]));
    if (results.every((result) => result.status === "rejected")) alertMessage("The console could not load operational data. Check the server log and database connection.", "error");
  }

  function showSection(name, updateHash = true) {
    document.querySelectorAll(".admin-section").forEach((section) => {
      const active = section.id === `section-${name}`;
      section.hidden = !active;
      section.classList.toggle("is-active", active);
    });
    document.querySelectorAll(".admin-nav button").forEach((button) => {
      const active = button.dataset.section === name;
      button.classList.toggle("is-active", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    if (updateHash) history.replaceState(null, "", `#${name}`);
    const heading = document.querySelector(`#section-${name} h1`);
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: false });
    }
  }

  function tableMessage(tbody, columns, message) {
    const row = element("tr");
    const cell = element("td", "muted", message);
    cell.colSpan = columns;
    row.append(cell);
    tbody.replaceChildren(row);
  }

  function actionButton(label, handler, danger = false) {
    const button = element("button", danger ? "row-button danger-text" : "row-button", label);
    button.type = "button";
    button.addEventListener("click", handler);
    return button;
  }

  function targetPayload(form) {
    const data = new FormData(form);
    return {
      name: String(data.get("name") || "").trim(),
      official_domains: lines(data.get("official_domains")),
      aliases: lines(data.get("aliases")),
      keywords: lines(data.get("keywords")),
      country: String(data.get("country") || "").trim().toUpperCase() || null,
      minimum_score: Number(data.get("minimum_score")) || 65,
      enabled: data.get("enabled") === "on",
    };
  }

  async function loadTargets() {
    const body = byId("target-rows");
    tableMessage(body, 6, "Loading watch targets…");
    try {
      const payload = await request("/targets");
      state.targets = list(first(payload, ["items", "targets", "results"], Array.isArray(payload) ? payload : []));
      renderTargets();
      renderSuppressionTargets();
      byId("admin-targets").textContent = state.targets.filter((target) => target.enabled !== false).length.toLocaleString();
    } catch (error) {
      tableMessage(body, 6, error.message);
      throw error;
    }
  }

  function renderTargets() {
    const body = byId("target-rows");
    body.replaceChildren();
    byId("target-empty").hidden = state.targets.length > 0;
    if (!state.targets.length) return;
    for (const target of state.targets) {
      const row = element("tr");
      const domains = lines(first(target, ["official_domains", "domains", "allowlist"], []));
      const terms = lines(target.aliases);
      const keywords = lines(target.keywords);
      row.append(
        element("td", "", first(target, ["name", "label"], "Unnamed target")),
        element("td", "muted", domains.length ? domains.slice(0, 2).map(defang).join(", ") + (domains.length > 2 ? ` +${domains.length - 2}` : "") : "None"),
        element("td", "muted", `${terms.length} aliases · ${keywords.length} context · score ≥${Number(first(target, ["minimum_score"], 65))}`),
      );
      const status = element("td");
      status.append(statusBadge(target.enabled === false ? "disabled" : "enabled"));
      row.append(status, element("td", "muted", formatDate(first(target, ["updated_at", "created_at"], null))));
      const actions = element("td", "row-actions");
      actions.append(actionButton("Edit", () => openTarget(target)), actionButton("Delete", () => deleteTarget(target), true));
      row.append(actions);
      body.append(row);
    }
  }

  function openTarget(target = null) {
    const form = byId("target-form");
    form.reset();
    setFormMessage("target-message");
    byId("target-dialog-title").textContent = target ? "Edit watch target" : "Add watch target";
    byId("target-id").value = target ? String(first(target, ["id", "uuid"], "")) : "";
    byId("target-name").value = target ? first(target, ["name", "label"], "") : "";
    byId("target-domains").value = target ? lines(first(target, ["official_domains", "domains", "allowlist"], [])).join("\n") : "";
    byId("target-aliases").value = target ? lines(target.aliases).join("\n") : "";
    byId("target-keywords").value = target ? lines(target.keywords).join("\n") : "";
    byId("target-country").value = target ? first(target, ["country"], "") : "";
    byId("target-minimum-score").value = target ? Number(first(target, ["minimum_score"], 65)) : 65;
    byId("target-enabled").checked = !target || target.enabled !== false;
    byId("target-dialog").showModal();
    byId("target-name").focus();
  }

  async function saveTarget(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const id = byId("target-id").value;
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    setFormMessage("target-message", "Saving…");
    try {
      await request(id ? `/targets/${encodeURIComponent(id)}` : "/targets", { method: id ? "PUT" : "POST", body: targetPayload(form) });
      byId("target-dialog").close();
      await loadTargets();
      alertMessage(id ? "Watch target updated." : "Watch target created.");
    } catch (error) {
      setFormMessage("target-message", error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function deleteTarget(target) {
    const id = first(target, ["id", "uuid"], "");
    const name = first(target, ["name", "label"], "this target");
    if (!id || !window.confirm(`Disable ${name}? Historical candidates will remain, but new matching will stop.`)) return;
    try {
      await request(`/targets/${encodeURIComponent(id)}`, { method: "DELETE" });
      await loadTargets();
      alertMessage("Watch target disabled.");
    } catch (error) {
      alertMessage(error.message, "error");
    }
  }

  function renderSuppressionTargets() {
    const select = byId("suppression-target");
    const selected = select.value;
    select.replaceChildren(new Option("Global", ""));
    for (const target of state.targets) select.add(new Option(`Target: ${first(target, ["name"], "Unnamed")}`, String(target.id)));
    if ([...select.options].some((option) => option.value === selected)) select.value = selected;
  }

  async function loadSuppressions() {
    const body = byId("suppression-rows");
    tableMessage(body, 6, "Loading suppressions…");
    try {
      const payload = await request("/suppressions");
      state.suppressions = list(first(payload, ["items", "suppressions", "results"], Array.isArray(payload) ? payload : []));
      renderSuppressions();
    } catch (error) {
      tableMessage(body, 6, error.message);
      throw error;
    }
  }

  function renderSuppressions() {
    const body = byId("suppression-rows");
    body.replaceChildren();
    if (!state.suppressions.length) {
      tableMessage(body, 6, "No suppression rules recorded.");
      return;
    }
    for (const item of state.suppressions) {
      const row = element("tr");
      const pattern = element("td");
      pattern.append(element("code", "", defang(item.pattern)));
      const target = state.targets.find((entry) => String(entry.id) === String(item.target_id));
      const status = element("td");
      status.append(statusBadge(item.enabled === false ? "disabled" : "enabled"));
      const actions = element("td", "row-actions");
      if (item.enabled !== false) actions.append(actionButton("Disable", () => disableSuppression(item), true));
      row.append(pattern, element("td", "muted", String(item.match_type || "exact")), element("td", "muted", target ? first(target, ["name"], "Target") : "Global"), element("td", "muted", first(item, ["reason"], "—")), status, actions);
      body.append(row);
    }
  }

  async function addSuppression(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const targetValue = String(data.get("target_id") || "");
    const payload = {
      pattern: String(data.get("pattern") || "").trim(),
      match_type: String(data.get("match_type") || "exact"),
      target_id: targetValue ? Number(targetValue) : null,
      reason: String(data.get("reason") || "").trim(),
    };
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    setFormMessage("suppression-message", "Saving suppression…");
    try {
      await request("/suppressions", { method: "POST", body: payload });
      form.reset();
      renderSuppressionTargets();
      await loadSuppressions();
      setFormMessage("suppression-message", "Suppression added.", true);
    } catch (error) {
      setFormMessage("suppression-message", error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function disableSuppression(item) {
    if (!window.confirm(`Disable suppression for ${item.pattern}? Historical review events remain unchanged.`)) return;
    try {
      await request(`/suppressions/${encodeURIComponent(item.id)}`, { method: "DELETE" });
      await loadSuppressions();
      alertMessage("Suppression disabled.");
    } catch (error) {
      alertMessage(error.message, "error");
    }
  }

  const providerDefaults = {
    certstream: { title: "CertStream", requires_key: false, description: "Live certificate transparency observations used to discover candidate domain names.", config: { key: "collection_seconds", label: "Collection window (seconds)", min: 5, max: 900, default: 240 } },
    urlscan: { title: "URLScan", requires_key: true, description: "Existing public scan evidence and bounded search pivots for candidate infrastructure.", config: { key: "result_limit", label: "Maximum results per pivot", min: 1, max: 100, default: 50 } },
    virustotal: { title: "VirusTotal", requires_key: true, description: "Optional passive domain-resolution relationships from authorised API access.", config: { key: "result_limit", label: "Maximum results per pivot", min: 1, max: 40, default: 40 } },
  };

  function providerName(provider) {
    return String(first(provider, ["name", "kind", "provider", "id"], "unknown")).toLowerCase();
  }

  function normalizeProviderState(provider) {
    const current = String(first(provider, ["status", "state", "last_status"], "")).toLowerCase().replaceAll(" ", "_");
    if (["ready", "disabled", "needs_key", "skipped", "error"].includes(current)) return current;
    if (["failed", "degraded"].includes(current)) return "error";
    if (["success", "healthy_empty"].includes(current)) return "ready";
    if (provider.enabled === false) return "disabled";
    if (provider.skipped === true) return "skipped";
    if (provider.error) return "error";
    const definition = providerDefaults[providerName(provider)] || {};
    if ((provider.requires_key ?? definition.requires_key) && !first(provider, ["has_secret", "configured", "has_api_key", "credential_configured"], false)) return "needs_key";
    return "ready";
  }

  function mergedProviders(payload) {
    const records = list(first(payload, ["items", "providers", "integrations"], Array.isArray(payload) ? payload : payload));
    const byName = new Map(records.map((record) => [providerName(record), record]));
    return Object.entries(providerDefaults).map(([name, defaults]) => ({ name, ...defaults, ...(byName.get(name) || {}) }));
  }

  async function loadProviders() {
    try {
      const payload = await request("/providers");
      state.providers = mergedProviders(payload);
      renderProviders();
      renderProviderOverview();
    } catch (error) {
      byId("provider-grid").replaceChildren(panelError("Unable to load providers", error.message));
      byId("overview-providers").replaceChildren(element("p", "muted", error.message));
      throw error;
    }
  }

  function panelError(title, message) {
    const panel = element("article", "panel");
    panel.append(element("strong", "", title), element("p", "muted", message));
    return panel;
  }

  function providerStatus(provider) {
    const value = normalizeProviderState(provider);
    return statusBadge(value);
  }

  function renderProviderOverview() {
    const wrap = byId("overview-providers");
    wrap.replaceChildren();
    for (const provider of state.providers) {
      const row = element("div", "mini-provider");
      row.append(element("strong", "", first(provider, ["title", "display_name", "name"], "Provider")), providerStatus(provider));
      row.append(element("small", "", normalizeProviderState(provider) === "ready" ? "Available for scheduled enrichment" : first(provider, ["message", "last_error"], "Optional provider will be skipped")));
      wrap.append(row);
    }
  }

  function renderProviders() {
    const grid = byId("provider-grid");
    grid.replaceChildren();
    for (const provider of state.providers) {
      const name = providerName(provider);
      const definition = providerDefaults[name] || {};
      const card = element("article", "provider-card");
      const head = element("div", "provider-card-head");
      const heading = element("div");
      heading.append(element("h2", "", first(provider, ["title", "display_name"], name)), element("span", "muted", name === "certstream" ? "Primary discovery" : "Optional enrichment"));
      head.append(heading, providerStatus(provider));
      card.append(head, element("p", "provider-description", first(provider, ["description"], definition.description || "External enrichment provider.")));

      const meta = element("div", "provider-meta");
      const lastRun = element("div");
      lastRun.append(element("span", "", "Last attempt"), element("span", "", formatDate(first(provider, ["last_run", "last_run_at", "last_tested_at", "updated_at"], null))));
      const outcome = element("div");
      outcome.append(element("span", "", "Outcome"), element("span", "", first(provider, ["message", "last_message", "last_result", "last_status"], normalizeProviderState(provider).replaceAll("_", " "))));
      meta.append(lastRun, outcome);
      card.append(meta);

      const form = element("form", "provider-form");
      form.dataset.provider = name;
      const toggleLabel = element("label", "switch-control");
      const toggle = element("input");
      toggle.type = "checkbox";
      toggle.name = "enabled";
      toggle.checked = provider.enabled !== false;
      toggleLabel.append(toggle, element("span", "", "Enable this provider"));
      form.append(toggleLabel);

      const configDefinition = definition.config;
      if (configDefinition) {
        const field = element("div", "field");
        const fieldLabel = element("label", "", configDefinition.label);
        fieldLabel.htmlFor = `provider-config-${slug(name)}`;
        const input = element("input");
        input.id = fieldLabel.htmlFor;
        input.name = "config_value";
        input.type = "number";
        input.min = String(configDefinition.min);
        input.max = String(configDefinition.max);
        input.required = true;
        input.value = String(provider.config?.[configDefinition.key] ?? configDefinition.default);
        field.append(fieldLabel, input);
        form.append(field);
      }

      if (provider.requires_key ?? definition.requires_key) {
        const field = element("div", "field");
        const fieldLabel = element("label", "", "API key");
        fieldLabel.htmlFor = `provider-key-${slug(name)}`;
        const input = element("input");
        input.id = fieldLabel.htmlFor;
        input.name = "api_key";
        input.type = "password";
        input.autocomplete = "new-password";
        const credentialSource = first(provider, ["credential_source"], "none");
        input.disabled = credentialSource === "environment";
        input.placeholder = credentialSource === "environment" ? "Configured by environment" : first(provider, ["has_secret", "configured", "has_api_key", "credential_configured"], false) ? "Saved — enter only to replace" : "Not configured";
        const hint = element("small", "", credentialSource === "environment" ? "Change the environment secret and restart both processes." : "Write-only: saved values are never returned to this browser.");
        field.append(fieldLabel, input, hint);
        form.append(field);
      }

      const message = element("p", "form-message");
      message.id = `provider-message-${slug(name)}`;
      form.append(message);
      const actions = element("div", "provider-actions");
      const save = element("button", "button button--primary button--small", "Save");
      save.type = "submit";
      const test = element("button", "button button--quiet button--small", name === "certstream" ? "Validate configuration" : "Test connection");
      test.type = "button";
      test.addEventListener("click", () => testProvider(name, message, test));
      actions.append(save, test);
      if ((provider.requires_key ?? definition.requires_key) && first(provider, ["credential_source"], "stored") === "stored" && first(provider, ["has_secret", "configured", "has_api_key", "credential_configured"], false)) {
        const remove = element("button", "button button--quiet button--small", "Remove key");
        remove.type = "button";
        remove.addEventListener("click", () => removeProviderSecret(name, message, remove));
        actions.append(remove);
      }
      form.append(actions);
      form.addEventListener("submit", saveProvider);
      card.append(form);
      grid.append(card);
    }
  }

  async function saveProvider(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = form.dataset.provider;
    const button = form.querySelector("button[type='submit']");
    const message = form.querySelector(".form-message");
    const secret = form.elements.namedItem("api_key");
    const definition = providerDefaults[name] || {};
    const payload = { enabled: form.elements.namedItem("enabled").checked };
    if (definition.config) payload.config = { [definition.config.key]: Number(form.elements.namedItem("config_value").value) };
    if (secret && secret.value.trim()) payload.api_key = secret.value.trim();
    button.disabled = true;
    message.textContent = "Saving…";
    try {
      await request(`/providers/${encodeURIComponent(name)}`, { method: "PUT", body: payload });
      if (secret) secret.value = "";
      await loadProviders();
      alertMessage(`${providerDefaults[name]?.title || name} configuration saved.`);
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function testProvider(name, message, button) {
    button.disabled = true;
    message.textContent = "Testing connection…";
    try {
      const result = await request(`/providers/${encodeURIComponent(name)}/test`, { method: "POST", body: {} });
      message.textContent = first(result, ["message", "detail"], "Connection test completed.");
      message.className = "form-message is-success";
      await loadProviders();
    } catch (error) {
      message.textContent = error.message;
      message.className = "form-message";
    } finally {
      button.disabled = false;
    }
  }

  async function removeProviderSecret(name, message, button) {
    if (!window.confirm(`Remove the saved ${providerDefaults[name]?.title || name} API key? Enrichment will be skipped until a new key is added.`)) return;
    button.disabled = true;
    try {
      await request(`/providers/${encodeURIComponent(name)}/secret`, { method: "DELETE" });
      await loadProviders();
      alertMessage("Provider key removed. Key-dependent enrichment will now be skipped.");
    } catch (error) {
      message.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function loadCandidates() {
    const body = byId("candidate-rows");
    tableMessage(body, 7, "Loading candidates…");
    const form = byId("candidate-filters");
    const data = new FormData(form);
    const params = new URLSearchParams();
    for (const name of ["query", "status"]) if (data.get(name)) params.set(name, data.get(name));
    params.set("page", String(state.candidatePage));
    params.set("limit", String(candidatePageSize()));
    try {
      const payload = await request(`/candidates${params.size ? `?${params}` : ""}`);
      state.candidates = list(first(payload, ["items", "candidates", "results"], Array.isArray(payload) ? payload : []));
      state.candidateTotal = Number(first(payload, ["total"], state.candidates.length)) || 0;
      state.candidatePage = Math.max(1, Number(first(payload, ["page"], state.candidatePage)) || 1);
      state.candidatePages = Math.max(1, Number(first(payload, ["pages"], Math.ceil(state.candidateTotal / candidatePageSize()))) || 1);
      if (state.candidateTotal > 0 && state.candidatePage > state.candidatePages) {
        state.candidatePage = state.candidatePages;
        return loadCandidates();
      }
      renderCandidates();
      renderCandidatePagination();
      const open = Number(first(payload, ["open_count"], state.candidates.filter((item) => String(item.status) === "potential").length));
      byId("review-count").textContent = String(open);
      byId("admin-candidates").textContent = open.toLocaleString();
    } catch (error) {
      tableMessage(body, 7, error.message);
      byId("candidate-pagination").hidden = true;
      throw error;
    }
  }

  function renderCandidatePagination() {
    const pagination = byId("candidate-pagination");
    const total = state.candidateTotal;
    pagination.hidden = total === 0 || state.candidatePages <= 1;
    byId("candidate-page-label").textContent = `Page ${state.candidatePage} of ${state.candidatePages} · ${total.toLocaleString()} results`;
    byId("candidate-page-previous").disabled = state.candidatePage <= 1;
    byId("candidate-page-next").disabled = state.candidatePage >= state.candidatePages;
  }

  function renderCandidates() {
    const body = byId("candidate-rows");
    body.replaceChildren();
    byId("candidate-empty").hidden = state.candidates.length > 0;
    for (const candidate of state.candidates) {
      const row = element("tr");
      const score = scoreValue(candidate);
      const scoreCell = element("td");
      scoreCell.append(element("span", scoreClass(score), `${score}/100`));
      const indicator = element("td");
      indicator.append(element("code", "", defang(signalDomain(candidate))));
      const evidenceCount = list(first(candidate, ["evidence", "reasons", "matches", "signals"], [])).length;
      const status = element("td");
      status.append(statusBadge(first(candidate, ["status", "review_status"], "potential")));
      const action = element("td");
      action.append(actionButton("Review", () => openReview(candidate)));
      row.append(scoreCell, indicator, element("td", "", targetName(candidate)), element("td", "muted", `${evidenceCount} signal${evidenceCount === 1 ? "" : "s"}`), element("td", "muted", formatDate(first(candidate, ["first_seen", "first_seen_at", "created_at"], null), false)), status, action);
      body.append(row);
    }
  }

  function detail(label, value, code = false) {
    const wrap = element("div");
    wrap.append(element("dt", "", label));
    const dd = element("dd");
    dd.append(code ? element("code", "", value) : document.createTextNode(value));
    wrap.append(dd);
    return wrap;
  }

  async function openReview(candidate) {
    state.selectedCandidate = candidate;
    updateReviewActions(candidate);
    const indicator = defang(signalDomain(candidate));
    byId("review-indicator").textContent = indicator;
    byId("review-note").value = "";
    setFormMessage("review-message");
    byId("review-details").replaceChildren(
      detail("Confidence", `${scoreValue(candidate)}/100`),
      detail("Status", String(first(candidate, ["status", "review_status"], "potential")).replaceAll("_", " ")),
      detail("Possible target", targetName(candidate)),
      detail("Sources", lines(first(candidate, ["sources", "source"], [])).join(", ") || "Unknown"),
      detail("First observed", formatDate(first(candidate, ["first_seen", "first_seen_at", "created_at"], null))),
      detail("Last observed", formatDate(first(candidate, ["last_seen", "last_seen_at", "updated_at"], null))),
      detail("Indicator", indicator, true),
      detail("Candidate ID", String(first(candidate, ["id", "uuid"], "Unknown")), true),
    );
    const evidenceList = byId("review-evidence");
    evidenceList.replaceChildren(element("li", "", "Loading source observations…"));
    byId("review-history").replaceChildren(element("li", "", "Loading review history…"));
    byId("review-dialog").showModal();
    try {
      const id = first(candidate, ["id", "uuid"], "");
      const detailRecord = await request(`/candidates/${encodeURIComponent(id)}`);
      state.selectedCandidate = detailRecord;
      updateReviewActions(detailRecord);
      const reasons = list(first(detailRecord, ["reasons", "matches", "signals"], []));
      const observations = list(detailRecord.observations);
      evidenceList.replaceChildren();
      for (const reason of reasons) evidenceList.append(element("li", "", `Match: ${typeof reason === "object" ? first(reason, ["summary", "reason", "label", "type"], JSON.stringify(reason)) : reason}`));
      for (const observation of observations) {
        const metadata = observation && typeof observation.payload === "object"
          ? Object.entries(observation.payload).filter(([, value]) => ["string", "number", "boolean"].includes(typeof value) && value !== "").slice(0, 6).map(([key, value]) => `${key}: ${String(value)}`).join(" · ")
          : "";
        evidenceList.append(element("li", "", `${first(observation, ["provider"], "source")} · ${formatDate(first(observation, ["observed_at"], null))}${metadata ? ` · ${metadata}` : ""}`));
      }
      if (!evidenceList.children.length) evidenceList.append(element("li", "", "No structured evidence was attached to this candidate."));
      const history = byId("review-history");
      history.replaceChildren();
      for (const event of list(detailRecord.review_events)) history.append(element("li", "", `${formatDate(event.created_at)} · ${String(first(event, ["action"], "review")).replaceAll("_", " ")} · ${first(event, ["reason"], "No note")}`));
      if (!history.children.length) history.append(element("li", "", "No analyst dispositions have been recorded."));
    } catch (error) {
      evidenceList.replaceChildren(element("li", "", `Evidence could not be loaded: ${error.message}`));
      byId("review-history").replaceChildren(element("li", "", "Review history is unavailable."));
    }
  }

  function allowedReviewActions(candidate) {
    const status = String(first(candidate, ["status", "review_status"], "potential"));
    if (["false_positive", "closed"].includes(status)) return new Set(["restore"]);
    if (status === "published") return new Set(["false_positive", "close"]);
    return new Set(["false_positive", "close", "publish"]);
  }

  function updateReviewActions(candidate) {
    const status = String(first(candidate, ["status", "review_status"], "potential"));
    const allowed = allowedReviewActions(candidate);
    document.querySelectorAll("[data-review-action]").forEach((button) => {
      const enabled = allowed.has(button.dataset.reviewAction);
      button.hidden = !enabled;
      button.disabled = !enabled;
    });
    const help = byId("review-transition-help");
    if (["false_positive", "closed"].includes(status)) {
      help.textContent = "Restore this candidate to review before it can be marked analyst-confirmed.";
    } else if (status === "published") {
      help.textContent = "This candidate is analyst-confirmed. Record a correction by closing it or marking it false positive.";
    } else {
      help.textContent = "Choose a disposition that reflects the evidence currently available. Marking a false positive also creates an exact suppression for this target.";
    }
  }

  async function reviewCandidate(decision, button) {
    const candidate = state.selectedCandidate;
    const id = candidate && first(candidate, ["id", "uuid"], "");
    if (!id) return;
    if (!allowedReviewActions(candidate).has(decision)) {
      setFormMessage("review-message", "That transition is not available from the candidate's current state.");
      return;
    }
    const note = byId("review-note").value.trim();
    if (["false_positive", "close"].includes(decision) && !note) {
      setFormMessage("review-message", "Add an analyst note before closing or marking a false positive.");
      byId("review-note").focus();
      return;
    }
    button.disabled = true;
    setFormMessage("review-message", "Saving disposition…");
    try {
      await request(`/candidates/${encodeURIComponent(id)}/review`, { method: "POST", body: { decision, note } });
      byId("review-dialog").close();
      state.selectedCandidate = null;
      await Promise.all([loadCandidates(), loadPublicStats(), loadSuppressions()]);
      const labels = { false_positive: "Candidate marked false positive.", restore: "Candidate restored to review.", publish: "Candidate marked analyst-confirmed.", close: "Candidate closed." };
      alertMessage(labels[decision] || "Disposition saved.");
    } catch (error) {
      setFormMessage("review-message", error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function loadPivots() {
    const body = byId("pivot-rows");
    tableMessage(body, 5, "Loading pivot queue…");
    try {
      const payload = await request("/pivots");
      state.pivots = list(first(payload, ["items", "pivots", "results", "queue"], Array.isArray(payload) ? payload : []));
      renderPivots();
      const queued = state.pivots.filter((pivot) => ["queued", "pending", "waiting"].includes(String(first(pivot, ["status", "state"], "queued")).toLowerCase())).length;
      byId("admin-pivots").textContent = queued.toLocaleString();
      byId("pivot-queue-summary").textContent = `${queued} waiting · ${state.pivots.length} shown`;
    } catch (error) {
      tableMessage(body, 5, error.message);
      throw error;
    }
  }

  function renderPivots() {
    const body = byId("pivot-rows");
    body.replaceChildren();
    if (!state.pivots.length) {
      tableMessage(body, 5, "No queued pivots.");
      return;
    }
    for (const pivot of state.pivots) {
      const row = element("tr");
      const indicator = element("td");
      indicator.append(element("code", "", defang(first(pivot, ["domain", "indicator"], "unknown"))));
      const status = element("td");
      status.append(statusBadge(first(pivot, ["status", "state"], "queued")));
      row.append(indicator, element("td", "muted", lines(first(pivot, ["providers", "provider"], [])).join(", ") || "Configured providers"), status, element("td", "muted", formatDate(first(pivot, ["queued_at", "created_at"], null))), element("td", "muted", first(pivot, ["requested_by", "operator"], "Operator")));
      body.append(row);
    }
  }

  async function queuePivot(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const domain = form.elements.namedItem("domain").value.trim().replace(/^https?:\/\//i, "").split("/")[0];
    const providers = [...form.querySelectorAll("input[name='providers']:checked")].map((input) => input.value);
    const button = form.querySelector("button[type='submit']");
    if (!domain) return;
    if (!providers.length) {
      alertMessage("Select at least one pivot provider before queuing the domain.", "warning");
      form.querySelector("input[name='providers']").focus();
      return;
    }
    button.disabled = true;
    try {
      const result = await request("/pivots", { method: "POST", body: { domain, providers, note: form.elements.namedItem("note").value.trim() } });
      await Promise.all([loadPivots(), loadRuns()]);
      let queued = lines(first(result, ["queued_providers"], []));
      if (!queued.length) queued = list(first(result, ["queued"], [])).map((item) => first(item, ["provider", "name"], "")).filter(Boolean);
      const skipped = lines(first(result, ["skipped_providers", "skipped"], []));
      if (queued.length) {
        form.reset();
        alertMessage(`Pivot queued for ${queued.join(", ")}.${skipped.length ? ` Skipped: ${skipped.join(", ")}.` : ""}`);
      } else {
        alertMessage(skipped.length ? `No pivot queued. Skipped: ${skipped.join(", ")}.` : "No pivot queued for the selected providers.", "warning");
      }
    } catch (error) {
      alertMessage(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async function loadRuns() {
    tableMessage(byId("run-rows"), 7, "Loading runs…");
    tableMessage(byId("overview-runs"), 5, "Loading runs…");
    try {
      const payload = await request("/runs");
      state.runs = list(first(payload, ["items", "runs", "results"], Array.isArray(payload) ? payload : []));
      renderRuns();
    } catch (error) {
      tableMessage(byId("run-rows"), 7, error.message);
      tableMessage(byId("overview-runs"), 5, error.message);
      throw error;
    }
  }

  function runCells(run, compact = false) {
    const id = String(first(run, ["id", "run_id", "uuid"], "—"));
    const statusCell = element("td");
    statusCell.append(statusBadge(first(run, ["status", "state"], "unknown")));
    const stats = typeof run.stats === "object" && run.stats ? run.stats : {};
    const processed = first(run, ["processed", "item_count", "count"], first(stats, ["processed", "messages", "observations", "candidates"], 0));
    const base = [element("td", "", id.length > 12 ? `${id.slice(0, 12)}…` : id), element("td", "muted", first(run, ["type", "kind", "job", "provider"], "collection")), statusCell, element("td", "muted", formatDate(first(run, ["started_at", "created_at"], null))), element("td", "muted", Number(processed).toLocaleString())];
    if (compact) return base;
    base.splice(4, 0, element("td", "muted", formatDate(first(run, ["finished_at", "completed_at"], null))));
    base.push(element("td", "muted", first(run, ["message", "note", "error"], "—")));
    return base;
  }

  function renderRuns() {
    const body = byId("run-rows");
    const overview = byId("overview-runs");
    body.replaceChildren();
    overview.replaceChildren();
    if (!state.runs.length) {
      tableMessage(body, 7, "No pipeline runs recorded.");
      tableMessage(overview, 5, "No pipeline runs recorded.");
      return;
    }
    for (const run of state.runs) {
      const row = element("tr");
      row.append(...runCells(run));
      body.append(row);
    }
    for (const run of state.runs.slice(0, 5)) {
      const row = element("tr");
      row.append(...runCells(run, true));
      overview.append(row);
    }
  }

  async function loadHealth() {
    try {
      const health = await publicRequest("/health");
      const status = String(first(health, ["status", "state"], "unknown")).toLowerCase();
      const latest = health.latest_collection || {};
      const badge = byId("admin-health-badge");
      badge.className = `status-badge status-${status === "ok" || status === "healthy" ? "ready" : slug(status)}`;
      badge.textContent = status;
      const records = [
        ["Last successful collection", formatDate(first(health, ["last_success", "last_collection", "updated_at"], first(latest, ["finished_at", "started_at"], null)))],
        ["Database", String(first(health, ["database", "database_status"], "connected")).replaceAll("_", " ")],
        ["Scheduler", String(first(health, ["scheduler", "scheduler_status"], first(latest, ["state"], "unknown"))).replaceAll("_", " ")],
      ];
      const listNode = byId("admin-health-list");
      listNode.replaceChildren();
      for (const [label, value] of records) {
        const item = element("div");
        item.append(element("dt", "", label), element("dd", "", value));
        listNode.append(item);
      }
      const database = byId("database-status");
      const databaseValue = String(first(health, ["database", "database_status"], "connected"));
      database.textContent = databaseValue;
      database.className = `status-badge status-${["ok", "healthy", "connected", "ready"].includes(databaseValue.toLowerCase()) ? "ready" : "error"}`;
    } catch (_) {
      byId("admin-health-badge").textContent = "Unavailable";
      byId("admin-health-badge").className = "status-badge status-error";
      byId("database-status").textContent = "Unknown";
    }
  }

  async function loadPublicStats() {
    try {
      const stats = await publicRequest("/stats");
      byId("admin-published").textContent = Number(first(stats, ["published", "total", "signals"], 0)).toLocaleString();
    } catch (_) {
      byId("admin-published").textContent = "—";
    }
  }

  byId("setup-recheck").addEventListener("click", bootstrap);

  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type='submit']");
    button.disabled = true;
    setFormMessage("login-message", "Signing in…");
    try {
      const result = await request("/login", { method: "POST", body: { username: form.elements.namedItem("username").value.trim(), password: form.elements.namedItem("password").value } });
      state.csrf = String(first(result, ["csrf_token", "csrf"], state.csrf));
      form.reset();
      await bootstrap();
    } catch (error) {
      setFormMessage("login-message", error.message);
    } finally {
      button.disabled = false;
    }
  });

  byId("logout-button").addEventListener("click", async () => {
    try { await request("/logout", { method: "POST", body: {} }); } catch (_) { /* Clear the local view even if the session has expired. */ }
    state.csrf = "";
    state.session = null;
    await bootstrap();
  });

  document.querySelectorAll(".admin-nav button[data-section]").forEach((button) => button.addEventListener("click", () => showSection(button.dataset.section)));
  document.querySelectorAll("[data-go-section]").forEach((button) => button.addEventListener("click", () => showSection(button.dataset.goSection)));
  document.querySelectorAll(".refresh-button").forEach((button) => button.addEventListener("click", async () => {
    button.disabled = true;
    await refreshWorkspace();
    button.disabled = false;
    alertMessage("Operational data refreshed.");
  }));

  byId("new-target-button").addEventListener("click", () => openTarget());
  byId("target-form").addEventListener("submit", saveTarget);
  byId("candidate-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.candidatePage = 1;
    loadCandidates();
  });
  byId("candidate-page-previous").addEventListener("click", () => {
    if (state.candidatePage <= 1) return;
    state.candidatePage -= 1;
    loadCandidates();
    byId("review-title").focus({ preventScroll: false });
  });
  byId("candidate-page-next").addEventListener("click", () => {
    if (state.candidatePage >= state.candidatePages) return;
    state.candidatePage += 1;
    loadCandidates();
    byId("review-title").focus({ preventScroll: false });
  });
  byId("pivot-form").addEventListener("submit", queuePivot);
  byId("suppression-form").addEventListener("submit", addSuppression);
  document.querySelectorAll("[data-review-action]").forEach((button) => button.addEventListener("click", () => reviewCandidate(button.dataset.reviewAction, button)));

  document.querySelectorAll("[data-close-dialog]").forEach((button) => button.addEventListener("click", () => byId(button.dataset.closeDialog).close()));
  document.querySelectorAll("dialog").forEach((dialog) => dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }));

  const preferencePageSize = byId("preference-page-size");
  const preferenceTime = byId("preference-time");
  preferencePageSize.value = String(candidatePageSize());
  preferenceTime.value = localStorage.getItem("odr-time") || "local";
  byId("preference-form").addEventListener("submit", (event) => {
    event.preventDefault();
    localStorage.setItem("odr-page-size", preferencePageSize.value);
    localStorage.setItem("odr-time", preferenceTime.value);
    state.candidatePage = 1;
    if (state.session) loadCandidates();
    alertMessage("Console preferences saved in this browser.");
  });

  window.addEventListener("hashchange", () => {
    const name = location.hash.replace("#", "");
    if (["overview", "targets", "integrations", "review", "pivots", "settings"].includes(name)) showSection(name, false);
  });

  bootstrap();
})();
