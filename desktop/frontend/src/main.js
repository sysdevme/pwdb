import "./style.css";

const emptySession = () => ({
  authenticated: false,
  token_present: false,
  user: null,
  server: null,
  passwords: [],
  notes: [],
});

const state = {
  settings: {
    server_url: "",
    email: "",
  },
  info: {
    name: "PWDB Desktop",
    version: "0.1.0-alpha",
    mode: "desktop-api-mvp",
  },
  connection: null,
  session: emptySession(),
  activeTab: "passwords",
  activeFilter: {
    kind: "all",
    value: "",
  },
  selectedId: "",
  selectedItem: null,
  unlockedItem: null,
  workspaceView: "list",
  settingsOpen: false,
  message: "",
  error: "",
};

async function callBackend(method, ...args) {
  const fn = window.go?.main?.App?.[method];
  if (!fn) {
    throw new Error(`Backend method ${method} is not available yet in this runtime.`);
  }
  return fn(...args);
}

async function hydrate() {
  try {
    state.info = await callBackend("GetAppInfo");
  } catch (_) {}
  try {
    state.settings = await callBackend("GetSettings");
  } catch (_) {}
  render();
}

function render() {
  const app = document.querySelector("#app");
  app.innerHTML = state.session.authenticated ? renderWorkspace() : renderWelcome();
  bindEvents();
}

function renderWelcome() {
  return `
    <main class="welcome-shell">
      <section class="welcome-hero">
        <div class="hero-copy">
          <p class="eyebrow">${escapeHtml(state.info.name)}</p>
          <h1>Desktop access for your vault, without the browser chrome.</h1>
          <p class="lede">
            Connect to a master or slave node, authenticate, and open your password and note records in a focused desktop workspace.
          </p>
        </div>
        <div class="hero-meta">
          <span class="pill">${escapeHtml(state.info.version)}</span>
          <span class="pill muted">${escapeHtml(state.info.mode)}</span>
        </div>
      </section>

      <section class="login-panel">
        <div class="panel-header">
          <h2>Connection</h2>
          <button id="test_btn" class="ghost">Test Connection</button>
        </div>
        <div class="form-grid">
          <label>
            <span>Server URL</span>
            <input id="server_url" type="url" placeholder="https://pwdb.example.com" value="${escapeHtml(state.settings.server_url || "")}" />
          </label>
          <label>
            <span>Email</span>
            <input id="email" type="email" placeholder="user@example.com" value="${escapeHtml(state.settings.email || "")}" />
          </label>
          <label class="form-span">
            <span>Login Password</span>
            <input id="login_password" type="password" placeholder="Login password" value="" />
          </label>
        </div>
        <div class="actions">
          <button id="save_btn">Save Settings</button>
          <button id="login_btn" class="primary">Login</button>
        </div>
        ${renderFeedback()}
        ${renderConnection()}
      </section>
    </main>
  `;
}

function renderWorkspace() {
  const items = getFilteredItems();
  const selected = state.selectedItem;
  return `
    <main class="workspace-shell">
      <header class="topbar">
        <div>
          <p class="eyebrow">${escapeHtml(state.info.name)}</p>
          <div class="topbar-title">
            <h1>${state.workspaceView === "detail" && selected ? escapeHtml(selected.title || "(untitled)") : "Vault"}</h1>
            <span class="pill">${escapeHtml(state.session.user?.email || "")}</span>
            <span class="pill muted">${escapeHtml(state.session.server?.mode || "node")}</span>
          </div>
        </div>
        <div class="topbar-actions">
          <button id="tab_passwords" class="${state.activeTab === "passwords" ? "tab-active" : ""}">Passwords</button>
          <button id="tab_notes" class="${state.activeTab === "notes" ? "tab-active" : ""}">Notes</button>
          <button id="settings_toggle" class="gear-button" aria-label="Connection settings">⚙</button>
        </div>
      </header>

      ${renderFeedback("workspace")}

      <section class="workspace-grid">
        <aside class="sidebar">
          <div class="sidebar-section">
            <h2>Browse</h2>
            <div class="tree-list">
              <button class="tree-node ${state.activeFilter.kind === "all" ? "active" : ""}" data-filter-kind="all" data-filter-value="">
                <span>All ${state.activeTab}</span>
                <strong>${getCurrentItems().length}</strong>
              </button>
            </div>
          </div>
          ${renderTreeSection("Groups", "group")}
          ${renderTreeSection("Tags", "tag")}
          ${renderTreeSection("Unnamed", "unnamed")}
        </aside>

        <section class="content-panel">
          <div class="content-header">
            <div>
              <h2>${state.workspaceView === "detail" ? "Record" : "Records"}</h2>
              <p>${escapeHtml(describeFilter())}</p>
            </div>
            <span class="pill muted">${items.length} item${items.length === 1 ? "" : "s"}</span>
          </div>
          ${state.workspaceView === "detail" ? renderDetailView() : renderListView(items)}
        </section>
      </section>

      ${renderSettingsDrawer()}
    </main>
  `;
}

function renderTreeSection(title, kind) {
  const nodes = buildTreeNodes(kind);
  return `
    <div class="sidebar-section">
      <h2>${title}</h2>
      <div class="tree-list">
        ${nodes.length === 0 ? `<p class="sidebar-empty">No ${title.toLowerCase()} yet.</p>` : nodes.map((node) => `
          <button class="tree-node ${state.activeFilter.kind === kind && state.activeFilter.value === node.value ? "active" : ""}" data-filter-kind="${kind}" data-filter-value="${escapeHtml(node.value)}">
            <span>${escapeHtml(node.label)}</span>
            <strong>${node.count}</strong>
          </button>
        `).join("")}
      </div>
    </div>
  `;
}

function renderListView(items) {
  if (items.length === 0) {
    return `<div class="empty-state"><p>No records match this filter.</p></div>`;
  }
  return `
    <div class="record-list">
      ${items.map((item) => renderListRow(item)).join("")}
    </div>
  `;
}

function renderListRow(item) {
  const subtitle = state.activeTab === "passwords"
    ? [item.username || "", item.url || ""].filter(Boolean).join(" · ")
    : [item.owner_email || "", formatCollections(item.tags, item.groups)].filter(Boolean).join(" · ");
  return `
    <button class="record-row ${state.selectedId === item.id ? "active" : ""}" data-record-id="${escapeHtml(item.id)}">
      <span class="record-row-title">${escapeHtml(item.title || "(untitled)")}</span>
      <span class="record-row-subtitle">${escapeHtml(subtitle || item.owner_email || "")}</span>
      <span class="record-row-meta">${escapeHtml(formatCollections(item.tags, item.groups) || "No groups or tags")}</span>
    </button>
  `;
}

function renderDetailView() {
  if (!state.selectedItem) {
    return `<div class="empty-state"><p>Select a record to open its detail view.</p></div>`;
  }
  const item = state.selectedItem;
  if (state.activeTab === "notes") {
    return `
      <div class="detail-view">
        <div class="detail-nav">
          <button id="back_to_list" class="ghost">← Back to list</button>
        </div>
        <div class="detail-card">
          <div class="detail-card-header">
            <h3>${escapeHtml(item.title || "(untitled)")}</h3>
            <span class="pill muted">${escapeHtml(item.owner_email || "")}</span>
          </div>
          <dl class="detail-grid">
            <div><dt>Tags</dt><dd>${escapeHtml(formatList(item.tags))}</dd></div>
            <div><dt>Groups</dt><dd>${escapeHtml(formatList(item.groups))}</dd></div>
          </dl>
          <label class="detail-label">
            <span>Master Password</span>
            <input id="master_password" type="password" placeholder="Required to reveal note body" value="" />
          </label>
          <div class="actions">
            <button id="unlock_note_btn" class="primary">Unlock Note</button>
          </div>
          ${state.unlockedItem ? `
            <div class="secret-card">
              <div><strong>Body</strong><p>${escapeHtml(state.unlockedItem.body || "")}</p></div>
            </div>
          ` : '<p class="placeholder">Note body stays hidden until you submit the master password.</p>'}
        </div>
      </div>
    `;
  }

  return `
    <div class="detail-view">
      <div class="detail-nav">
        <button id="back_to_list" class="ghost">← Back to list</button>
      </div>
      <div class="detail-card">
        <div class="detail-card-header">
          <h3>${escapeHtml(item.title || "(untitled)")}</h3>
          <span class="pill muted">${escapeHtml(item.owner_email || "")}</span>
        </div>
        <dl class="detail-grid">
          <div><dt>Username</dt><dd>${escapeHtml(item.username || "Not set")}</dd></div>
          <div><dt>URL</dt><dd>${escapeHtml(item.url || "Not set")}</dd></div>
          <div><dt>Tags</dt><dd>${escapeHtml(formatList(item.tags))}</dd></div>
          <div><dt>Groups</dt><dd>${escapeHtml(formatList(item.groups))}</dd></div>
        </dl>
        <label class="detail-label">
          <span>Master Password</span>
          <input id="master_password" type="password" placeholder="Required to reveal secret fields" value="" />
        </label>
        <div class="actions">
          <button id="unlock_btn" class="primary">Unlock Item</button>
        </div>
        ${state.unlockedItem ? `
          <div class="secret-card">
            <div><strong>Password</strong><p>${escapeHtml(state.unlockedItem.password || "")}</p></div>
            <div><strong>Notes</strong><p>${escapeHtml(state.unlockedItem.notes || "")}</p></div>
          </div>
        ` : '<p class="placeholder">Secret fields stay hidden until you submit the master password.</p>'}
      </div>
    </div>
  `;
}

function renderSettingsDrawer() {
  return `
    <aside class="settings-drawer ${state.settingsOpen ? "open" : ""}">
      <div class="settings-panel">
        <div class="panel-header">
          <h2>Connection Settings</h2>
          <button id="close_settings" class="ghost">Close</button>
        </div>
        <div class="form-grid">
          <label>
            <span>Server URL</span>
            <input id="server_url" type="url" placeholder="https://pwdb.example.com" value="${escapeHtml(state.settings.server_url || "")}" />
          </label>
          <label>
            <span>Email</span>
            <input id="email" type="email" placeholder="user@example.com" value="${escapeHtml(state.settings.email || "")}" />
          </label>
          <label class="form-span">
            <span>Login Password</span>
            <input id="login_password" type="password" placeholder="Required only when you log in again" value="" />
          </label>
        </div>
        <div class="actions">
          <button id="save_btn">Save Settings</button>
          <button id="test_btn">Test Connection</button>
          <button id="logout_btn">Logout</button>
        </div>
        ${renderConnection()}
      </div>
    </aside>
  `;
}

function renderFeedback(mode = "default") {
  if (!state.message && !state.error) {
    return "";
  }
  return `
    <div class="feedback-stack ${mode}">
      ${state.message ? `<p class="message ok">${escapeHtml(state.message)}</p>` : ""}
      ${state.error ? `<p class="message error">${escapeHtml(state.error)}</p>` : ""}
    </div>
  `;
}

function renderConnection() {
  if (!state.connection) return "";
  const statusClass = state.connection.reachable ? "ok" : "error";
  return `
    <div class="connection-card ${statusClass}">
      <strong>${state.connection.reachable ? "Reachable" : "Unreachable"}</strong>
      <p>${escapeHtml(state.connection.description || "")}</p>
      <p class="meta">Status code: ${escapeHtml(String(state.connection.status_code || 0))}</p>
    </div>
  `;
}

function bindEvents() {
  document.querySelector("#save_btn")?.addEventListener("click", saveSettings);
  document.querySelector("#test_btn")?.addEventListener("click", testConnection);
  document.querySelector("#login_btn")?.addEventListener("click", login);
  document.querySelector("#logout_btn")?.addEventListener("click", logout);
  document.querySelector("#tab_passwords")?.addEventListener("click", () => switchTab("passwords"));
  document.querySelector("#tab_notes")?.addEventListener("click", () => switchTab("notes"));
  document.querySelector("#settings_toggle")?.addEventListener("click", toggleSettings);
  document.querySelector("#close_settings")?.addEventListener("click", toggleSettings);
  document.querySelector("#back_to_list")?.addEventListener("click", backToList);
  document.querySelector("#unlock_btn")?.addEventListener("click", unlockPassword);
  document.querySelector("#unlock_note_btn")?.addEventListener("click", unlockNote);

  document.querySelectorAll("[data-record-id]").forEach((button) => {
    button.addEventListener("click", () => selectRecord(button.dataset.recordId));
  });
  document.querySelectorAll("[data-filter-kind]").forEach((button) => {
    button.addEventListener("click", () => applyFilter(button.dataset.filterKind, button.dataset.filterValue || ""));
  });
}

async function saveSettings() {
  clearFeedback();
  const settings = readSettingsFromForm();
  try {
    state.settings = await callBackend("SaveSettings", settings);
    state.message = "Settings saved locally.";
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

async function testConnection() {
  clearFeedback();
  const settings = readSettingsFromForm();
  try {
    state.connection = await callBackend("TestConnection", settings);
    state.message = state.connection.reachable ? "Connection test completed." : "";
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

async function login() {
  clearFeedback();
  const settings = readSettingsFromForm();
  const password = document.querySelector("#login_password")?.value || "";
  try {
    state.session = await callBackend("Login", settings, password);
    state.settings = settings;
    state.connection = null;
    state.settingsOpen = false;
    state.activeTab = "passwords";
    state.activeFilter = { kind: "all", value: "" };
    state.selectedId = "";
    state.selectedItem = null;
    state.unlockedItem = null;
    state.workspaceView = "list";
    state.message = `Logged in as ${state.session.user?.email || settings.email}.`;
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

async function logout() {
  clearFeedback();
  try {
    await callBackend("Logout");
    state.session = emptySession();
    state.activeTab = "passwords";
    state.activeFilter = { kind: "all", value: "" };
    state.selectedId = "";
    state.selectedItem = null;
    state.unlockedItem = null;
    state.workspaceView = "list";
    state.settingsOpen = false;
    state.message = "Logged out.";
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

async function selectRecord(id) {
  clearFeedback();
  state.selectedId = id;
  state.unlockedItem = null;
  state.workspaceView = "detail";
  try {
    state.selectedItem = state.activeTab === "passwords"
      ? await callBackend("GetPassword", id)
      : await callBackend("GetNote", id);
  } catch (error) {
    state.error = describeError(error);
    state.workspaceView = "list";
  }
  render();
}

async function unlockPassword() {
  if (!state.selectedId) return;
  clearFeedback();
  const masterPassword = document.querySelector("#master_password")?.value || "";
  try {
    state.unlockedItem = await callBackend("UnlockPassword", state.selectedId, masterPassword);
    state.message = "Secret fields loaded.";
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

async function unlockNote() {
  if (!state.selectedId) return;
  clearFeedback();
  const masterPassword = document.querySelector("#master_password")?.value || "";
  try {
    state.unlockedItem = await callBackend("UnlockNote", state.selectedId, masterPassword);
    state.message = "Note body loaded.";
  } catch (error) {
    state.error = describeError(error);
  }
  render();
}

function switchTab(tab) {
  if (state.activeTab === tab) return;
  clearFeedback();
  state.activeTab = tab;
  state.activeFilter = { kind: "all", value: "" };
  state.selectedId = "";
  state.selectedItem = null;
  state.unlockedItem = null;
  state.workspaceView = "list";
  render();
}

function toggleSettings() {
  state.settingsOpen = !state.settingsOpen;
  render();
}

function backToList() {
  state.workspaceView = "list";
  state.unlockedItem = null;
  render();
}

function applyFilter(kind, value) {
  clearFeedback();
  state.activeFilter = { kind, value };
  state.workspaceView = "list";
  state.selectedId = "";
  state.selectedItem = null;
  state.unlockedItem = null;
  render();
}

function getCurrentItems() {
  return state.activeTab === "passwords" ? (state.session.passwords || []) : (state.session.notes || []);
}

function getFilteredItems() {
  const items = getCurrentItems();
  const { kind, value } = state.activeFilter;
  if (kind === "all") {
    return items;
  }
  if (kind === "group") {
    return items.filter((item) => (item.groups || []).includes(value));
  }
  if (kind === "tag") {
    return items.filter((item) => (item.tags || []).includes(value));
  }
  if (kind === "unnamed") {
    return items.filter((item) => (item.groups || []).length === 0 && (item.tags || []).length === 0);
  }
  return items;
}

function buildTreeNodes(kind) {
  const items = getCurrentItems();
  if (kind === "unnamed") {
    const count = items.filter((item) => (item.groups || []).length === 0 && (item.tags || []).length === 0).length;
    return count > 0 ? [{ label: "Without groups or tags", value: "unnamed", count }] : [];
  }

  const values = new Map();
  const field = kind === "group" ? "groups" : "tags";
  items.forEach((item) => {
    (item[field] || []).forEach((entry) => {
      const key = String(entry || "").trim();
      if (!key) return;
      values.set(key, (values.get(key) || 0) + 1);
    });
  });

  return [...values.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([value, count]) => ({
      label: value,
      value,
      count,
    }));
}

function describeFilter() {
  const { kind, value } = state.activeFilter;
  if (kind === "all") {
    return `Showing all ${state.activeTab}.`;
  }
  if (kind === "group") {
    return `Filtered by group: ${value}`;
  }
  if (kind === "tag") {
    return `Filtered by tag: ${value}`;
  }
  if (kind === "unnamed") {
    return "Showing records without groups or tags.";
  }
  return "";
}

function formatCollections(tags, groups) {
  const chunks = [];
  if ((groups || []).length > 0) {
    chunks.push(`Groups: ${(groups || []).join(", ")}`);
  }
  if ((tags || []).length > 0) {
    chunks.push(`Tags: ${(tags || []).join(", ")}`);
  }
  return chunks.join(" · ");
}

function formatList(values) {
  return (values || []).length > 0 ? values.join(", ") : "None";
}

function readSettingsFromForm() {
  return {
    server_url: document.querySelector("#server_url")?.value || "",
    email: document.querySelector("#email")?.value || "",
  };
}

function clearFeedback() {
  state.message = "";
  state.error = "";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function describeError(error) {
  if (!error) {
    return "Unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (typeof error.message === "string" && error.message.trim() !== "") {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch (_) {
    return String(error);
  }
}

hydrate();
