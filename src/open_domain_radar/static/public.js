(() => {
  "use strict";

  const API_ROOT = "/api/public/v1";
  const state = { page: 1, pageSize: 25, pages: 1, total: 0, signals: [], controller: null };
  const byId = (id) => document.getElementById(id);
  const filters = byId("signal-filters");
  const rows = byId("signal-rows");
  const tableWrap = byId("signal-table-wrap");
  const statePanel = byId("signal-state");
  const pagination = byId("pagination");
  const dialog = byId("signal-dialog");

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  async function request(path, options = {}) {
    const response = await fetch(`${API_ROOT}${path}`, {
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    });
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        message = body.detail || body.message || message;
      } catch (_) {
        // The status code remains useful when a proxy returns a non-JSON error.
      }
      throw new Error(message);
    }
    return response.json();
  }

  function list(value) {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (value === null || value === undefined || value === "") return [];
    return [value];
  }

  function first(object, keys, fallback = "—") {
    for (const key of keys) {
      if (object && object[key] !== undefined && object[key] !== null && object[key] !== "") return object[key];
    }
    return fallback;
  }

  function defang(value) {
    let output = String(value || "unknown").trim();
    output = output.replace(/^https:/i, "hxxps:").replace(/^http:/i, "hxxp:");
    output = output.replace(/\[\.\]/g, "\u0000").replace(/\./g, "[.]").replace(/\u0000/g, "[.]");
    return output;
  }

  function formatDate(value, includeTime = false) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return String(value);
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      ...(includeTime ? { timeStyle: "short" } : {}),
    }).format(date);
  }

  function relativeDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return String(value);
    const seconds = Math.round((date.valueOf() - Date.now()) / 1000);
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    const ranges = [[86400, "day"], [3600, "hour"], [60, "minute"]];
    for (const [size, unit] of ranges) {
      if (Math.abs(seconds) >= size) return formatter.format(Math.round(seconds / size), unit);
    }
    return formatter.format(seconds, "second");
  }

  function slug(value) {
    return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  }

  function signalDomain(signal) {
    return first(signal, ["defanged", "observable", "indicator", "domain", "hostname", "url"], "unknown");
  }

  function targetName(signal) {
    const target = first(signal, ["target", "target_name", "brand", "watch_target"], "Unspecified");
    return typeof target === "object" ? first(target, ["name", "label"], "Unspecified") : target;
  }

  function sourceName(signal) {
    const sources = list(first(signal, ["sources", "source"], []));
    return sources.map((item) => typeof item === "object" ? first(item, ["name", "provider"], "Unknown") : item).join(", ") || "Unknown";
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
    const status = String(value || "potential").replaceAll("_", " ");
    return element("span", `status-badge status-${slug(status)}`, status);
  }

  function setLoading() {
    tableWrap.hidden = true;
    pagination.hidden = true;
    statePanel.hidden = false;
    statePanel.className = "state-panel";
    statePanel.replaceChildren(
      element("span", "spinner"),
      (() => {
        const wrap = element("div");
        wrap.append(element("strong", "", "Loading signals"), element("p", "", "Requesting the current public catalogue."));
        return wrap;
      })(),
    );
  }

  function setMessage(title, message, isError = false) {
    tableWrap.hidden = true;
    pagination.hidden = true;
    statePanel.hidden = false;
    statePanel.className = `state-panel${isError ? " state-panel--error" : ""}`;
    const wrap = element("div");
    wrap.append(element("strong", "", title), element("p", "", message));
    if (isError) {
      const retry = element("button", "button button--quiet button--small", "Try again");
      retry.type = "button";
      retry.addEventListener("click", loadSignals);
      wrap.append(retry);
    }
    statePanel.replaceChildren(wrap);
  }

  function cell(text, className = "") {
    return element("td", className, text);
  }

  function renderRows(signals) {
    rows.replaceChildren();
    for (const signal of signals) {
      const row = element("tr");
      const score = scoreValue(signal);
      const scoreCell = element("td");
      scoreCell.append(element("span", scoreClass(score), `${score}/100`));

      const indicatorCell = element("td");
      indicatorCell.append(element("code", "", defang(signalDomain(signal))));
      const targetCell = cell(targetName(signal));
      const sourceCell = cell(sourceName(signal), "muted");
      const firstSeen = cell(formatDate(first(signal, ["first_seen", "first_seen_at", "created_at", "observed_at"], null)));
      const lastSeen = cell(formatDate(first(signal, ["last_seen", "last_seen_at", "updated_at", "observed_at"], null)));
      const statusCell = element("td");
      statusCell.append(statusBadge(first(signal, ["status", "review_status"], "potential")));
      const actionCell = element("td");
      const button = element("button", "row-button", "Inspect");
      button.type = "button";
      button.setAttribute("aria-label", `Inspect ${defang(signalDomain(signal))}`);
      button.addEventListener("click", () => openSignal(signal));
      actionCell.append(button);
      row.append(scoreCell, indicatorCell, targetCell, sourceCell, firstSeen, lastSeen, statusCell, actionCell);
      rows.append(row);
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

  function openSignal(signal) {
    const indicator = defang(signalDomain(signal));
    byId("dialog-indicator").textContent = indicator;
    const details = byId("signal-details");
    details.replaceChildren(
      detail("Confidence", `${scoreValue(signal)}/100`),
      detail("Status", String(first(signal, ["status", "review_status"], "potential")).replaceAll("_", " ")),
      detail("Possible target", targetName(signal)),
      detail("Sources", sourceName(signal)),
      detail("First observed", formatDate(first(signal, ["first_seen", "first_seen_at", "created_at", "observed_at"], null), true)),
      detail("Last observed", formatDate(first(signal, ["last_seen", "last_seen_at", "updated_at", "observed_at"], null), true)),
      detail("Indicator", indicator, true),
      detail("Record ID", String(first(signal, ["public_id", "id", "uuid"], "Unavailable")), true),
    );

    const evidence = list(first(signal, ["reasons", "evidence", "matches", "signals"], []));
    const evidenceList = byId("signal-evidence");
    evidenceList.replaceChildren();
    if (!evidence.length) evidenceList.append(element("li", "", "No detailed matching rationale is available."));
    for (const item of evidence) {
      const text = typeof item === "object"
        ? first(item, ["summary", "reason", "label", "type"], JSON.stringify(item))
        : item;
      evidenceList.append(element("li", "", text));
    }
    byId("signal-provenance").textContent = String(first(signal, ["provenance", "source_note", "collection_note"], "The record was normalized from the listed sources and reviewed under this deployment’s publication policy."));
    dialog.showModal();
  }

  function paramsFromForm() {
    const data = new FormData(filters);
    return {
      query: String(data.get("query") || "").trim(),
      status: String(data.get("status") || ""),
      source: String(data.get("source") || ""),
      target: String(data.get("target") || ""),
      page: state.page,
      page_size: state.pageSize,
    };
  }

  function updateAddress(params) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value && !(key === "page" && value === 1) && !(key === "page_size" && value === 25)) query.set(key, value);
    }
    const next = query.size ? `${location.pathname}?${query}` : location.pathname;
    history.replaceState(null, "", next);
  }

  function hydrateAddress() {
    const params = new URLSearchParams(location.search);
    for (const name of ["query", "status", "source", "target"]) {
      const control = filters.elements.namedItem(name);
      if (control && params.has(name)) control.value = params.get(name);
    }
    state.page = Math.max(1, Number(params.get("page")) || 1);
    state.pageSize = [10, 25, 50].includes(Number(params.get("page_size"))) ? Number(params.get("page_size")) : 25;
    byId("page-size").value = String(state.pageSize);
  }

  function addOptions(select, values) {
    const selected = select.value;
    const existing = new Set([...select.options].map((option) => option.value));
    for (const raw of values) {
      const value = typeof raw === "object" ? first(raw, ["name", "label", "value"], "") : raw;
      if (!value || existing.has(String(value))) continue;
      const option = element("option", "", value);
      option.value = String(value);
      select.append(option);
      existing.add(String(value));
    }
    select.value = selected;
  }

  async function loadSignals() {
    if (state.controller) state.controller.abort();
    state.controller = new AbortController();
    setLoading();
    const params = paramsFromForm();
    updateAddress(params);
    const query = new URLSearchParams(Object.entries(params).map(([key, value]) => [key, String(value)]));
    try {
      const payload = await request(`/signals?${query}`, { signal: state.controller.signal });
      const signals = list(first(payload, ["items", "signals", "results"], Array.isArray(payload) ? payload : []));
      state.signals = signals;
      const pageMeta = payload.pagination || payload.meta || {};
      state.total = Number(first(payload, ["total", "count"], first(pageMeta, ["total", "count"], signals.length))) || 0;
      state.page = Number(first(payload, ["page", "current_page"], first(pageMeta, ["page", "current_page"], state.page))) || 1;
      state.pages = Number(first(payload, ["pages", "total_pages"], first(pageMeta, ["pages", "total_pages"], Math.max(1, Math.ceil(state.total / state.pageSize))))) || 1;
      byId("result-summary").textContent = state.total === 1 ? "1 public signal" : `${state.total.toLocaleString()} public signals`;
      if (!signals.length) {
        setMessage("No matching signals", "Try broadening the search or removing one of the filters.");
        return;
      }
      renderRows(signals);
      statePanel.hidden = true;
      tableWrap.hidden = false;
      pagination.hidden = state.pages <= 1;
      byId("page-label").textContent = `Page ${state.page} of ${state.pages}`;
      byId("page-previous").disabled = state.page <= 1;
      byId("page-next").disabled = state.page >= state.pages;
      addOptions(byId("filter-source"), signals.flatMap((item) => list(first(item, ["sources", "source"], []))));
      addOptions(byId("filter-target"), signals.map(targetName));
    } catch (error) {
      if (error.name === "AbortError") return;
      byId("result-summary").textContent = "Signal catalogue unavailable";
      setMessage("Unable to load signals", `${error.message}. The public API may be temporarily unavailable.`, true);
    }
  }

  async function loadStats() {
    try {
      const stats = await request("/stats");
      byId("metric-total").textContent = Number(first(stats, ["signals", "total", "published"], 0)).toLocaleString();
      byId("metric-new").textContent = Number(first(stats, ["observed_24h", "new_24h", "last_24_hours"], 0)).toLocaleString();
      byId("metric-targets").textContent = Number(first(stats, ["targets", "watch_targets", "target_count"], 0)).toLocaleString();
      const updated = first(stats, ["last_collection"], null);
      byId("metric-updated").textContent = updated ? relativeDate(updated) : "No run";
      byId("metric-source-note").textContent = updated ? formatDate(updated, true) : "No completed collection reported";
      addOptions(byId("filter-source"), list(first(stats, ["sources", "source_facets"], [])));
      addOptions(byId("filter-target"), list(first(stats, ["targets_list", "target_facets"], [])));
    } catch (_) {
      byId("metric-source-note").textContent = "Statistics temporarily unavailable";
    }
  }

  async function loadHealth() {
    const label = byId("service-health");
    const dot = byId("health-dot");
    try {
      const health = await request("/health");
      const status = String(first(health, ["status", "state"], "unknown")).toLowerCase();
      dot.className = `health-dot health-dot--${status === "ok" ? "healthy" : slug(status)}`;
      const latest = health.latest_collection || {};
      label.textContent = status === "ok" || status === "healthy"
        ? `Collection pipeline reports healthy${latest.provider ? ` · ${latest.provider}` : ""}`
        : `Collection state: ${status.replaceAll("_", " ")}`;
    } catch (_) {
      dot.className = "health-dot health-dot--unknown";
      label.textContent = "Collection health unavailable";
    }
  }

  filters.addEventListener("submit", (event) => {
    event.preventDefault();
    state.page = 1;
    loadSignals();
  });

  filters.addEventListener("reset", () => {
    window.setTimeout(() => {
      state.page = 1;
      state.pageSize = 25;
      byId("page-size").value = "25";
      loadSignals();
    }, 0);
  });

  byId("page-size").addEventListener("change", (event) => {
    state.pageSize = Number(event.target.value);
    state.page = 1;
    loadSignals();
  });

  byId("page-previous").addEventListener("click", () => {
    if (state.page > 1) { state.page -= 1; loadSignals(); document.querySelector("#signals-title").focus?.(); }
  });
  byId("page-next").addEventListener("click", () => {
    if (state.page < state.pages) { state.page += 1; loadSignals(); document.querySelector("#signals-title").focus?.(); }
  });

  byId("dialog-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); });
  window.addEventListener("popstate", () => { hydrateAddress(); loadSignals(); });

  hydrateAddress();
  Promise.allSettled([loadSignals(), loadStats(), loadHealth()]);
})();
