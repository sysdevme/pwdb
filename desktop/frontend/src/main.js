import "./style.css";

const state = {
  settings: {
    server_url: "",
    email: "",
  },
  info: {
    name: "PWDB Desktop",
    version: "0.1.0-alpha",
    mode: "read-only-shell",
  },
  connection: null,
  session: {
    authenticated: false,
    token_present: false,
    user: null,
    server: null,
    passwords: [],
    notes: [],
  },
  activeTab: "passwords",
  selectedId: "",
  selectedItem: null,
  unlockedItem: null,
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
  app.innerHTML = `
    <main class="shell">
      <section class="hero">
        <p class="eyebrow">${state.info.name}</p>
        <h1>macOS desktop client scaffold</h1>
        <p class="lede">
          This is a read-only shell for future master/slave node access.
          Current mode: <strong>${state.info.mode}</strong>
        </p>
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Connection</h2>
          <span class="pill">${state.info.version}</span>
        </div>
        <label>
          <span>Server URL</span>
          <input id="server_url" type="url" placeholder="https://pwdb.example.com" value="${escapeHtml(state.settings.server_url || "")}" />
        </label>
        <label>
          <span>Email</span>
          <input id="email" type="email" placeholder="user@example.com" value="${escapeHtml(state.settings.email || "")}" />
        </label>
        <label>
          <span>Login Password</span>
          <input id="login_password" type="password" placeholder="Login password" value="" />
        </label>
        <div class="actions">
          <button id="save_btn" class="primary">Save Settings</button>
          <button id="test_btn">Test Connection</button>
          ${state.session.authenticated ? '<button id="logout_btn">Logout</button>' : '<button id="login_btn">Login</button>'}
        </div>
        ${state.message ? `<p class="message ok">${escapeHtml(state.message)}</p>` : ""}
        ${state.error ? `<p class="message error">${escapeHtml(state.error)}</p>` : ""}
        ${renderConnection()}
      </section>

      <section class="panel">
        <div class="panel-header">
          <h2>Vault</h2>
          <span class="pill muted">${state.session.authenticated ? "Read-only" : "Disconnected"}</span>
        </div>
        ${state.session.authenticated ? `
          <div class="tabbar">
            <button id="tab_passwords" class="${state.activeTab === "passwords" ? "tab-active" : ""}">Passwords</button>
            <button id="tab_notes" class="${state.activeTab === "notes" ? "tab-active" : ""}">Notes</button>
          </div>
        ` : ""}
        ${renderVault()}
      </section>
    </main>
  `;

  document.querySelector("#save_btn")?.addEventListener("click", saveSettings);
  document.querySelector("#test_btn")?.addEventListener("click", testConnection);
  document.querySelector("#login_btn")?.addEventListener("click", login);
  document.querySelector("#logout_btn")?.addEventListener("click", logout);
  document.querySelector("#tab_passwords")?.addEventListener("click", () => switchTab("passwords"));
  document.querySelector("#tab_notes")?.addEventListener("click", () => switchTab("notes"));
  document.querySelectorAll("[data-password-id]").forEach((button) => {
    button.addEventListener("click", () => selectPassword(button.dataset.passwordId));
  });
  document.querySelectorAll("[data-note-id]").forEach((button) => {
    button.addEventListener("click", () => selectNote(button.dataset.noteId));
  });
  document.querySelector("#unlock_btn")?.addEventListener("click", unlockPassword);
  document.querySelector("#unlock_note_btn")?.addEventListener("click", unlockNote);
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

function renderVault() {
  if (!state.session.authenticated) {
    return `<p class="placeholder">Login first to load your password list from the selected master or slave node.</p>`;
  }
  const isPasswords = state.activeTab === "passwords";
  const items = isPasswords ? (state.session.passwords || []) : (state.session.notes || []);
  return `
    <div class="vault-grid">
      <div class="vault-list">
        <h3>${isPasswords ? "Passwords" : "Notes"}</h3>
        ${items.length === 0 ? `<p class="placeholder">No ${isPasswords ? "passwords" : "notes"} returned for this user.</p>` : ""}
        ${items.map((item) => `
          <button class="vault-row ${state.selectedId === item.id ? "active" : ""}" ${isPasswords ? `data-password-id="${escapeHtml(item.id)}"` : `data-note-id="${escapeHtml(item.id)}"`}>
            <strong>${escapeHtml(item.title || "(untitled)")}</strong>
            <span>${escapeHtml(isPasswords ? (item.username || "") : (item.owner_email || ""))}</span>
          </button>
        `).join("")}
      </div>
      <div class="vault-detail">
        ${renderDetail()}
      </div>
    </div>
  `;
}

function renderDetail() {
  if (!state.selectedItem) {
    return `<p class="placeholder">Select an item to view its metadata.</p>`;
  }
  if (state.activeTab === "notes") {
    return `
      <h3>${escapeHtml(state.selectedItem.title || "(untitled)")}</h3>
      <dl class="detail-grid">
        <div><dt>Owner</dt><dd>${escapeHtml(state.selectedItem.owner_email || "")}</dd></div>
        <div><dt>Tags</dt><dd>${escapeHtml((state.selectedItem.tags || []).join(", "))}</dd></div>
        <div><dt>Groups</dt><dd>${escapeHtml((state.selectedItem.groups || []).join(", "))}</dd></div>
      </dl>
      <label>
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
    `;
  }
  return `
    <h3>${escapeHtml(state.selectedItem.title || "(untitled)")}</h3>
    <dl class="detail-grid">
      <div><dt>Username</dt><dd>${escapeHtml(state.selectedItem.username || "")}</dd></div>
      <div><dt>URL</dt><dd>${escapeHtml(state.selectedItem.url || "")}</dd></div>
      <div><dt>Owner</dt><dd>${escapeHtml(state.selectedItem.owner_email || "")}</dd></div>
      <div><dt>Tags</dt><dd>${escapeHtml((state.selectedItem.tags || []).join(", "))}</dd></div>
      <div><dt>Groups</dt><dd>${escapeHtml((state.selectedItem.groups || []).join(", "))}</dd></div>
    </dl>
    <label>
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
  `;
}

async function saveSettings() {
  clearFeedback();
  const settings = readSettingsFromForm();
  try {
    state.settings = await callBackend("SaveSettings", settings);
    state.message = "Settings saved locally.";
  } catch (error) {
    state.error = error.message;
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
    state.error = error.message;
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
    state.selectedId = "";
    state.selectedItem = null;
    state.unlockedItem = null;
    state.activeTab = "passwords";
    state.message = `Logged in as ${state.session.user?.email || settings.email}.`;
  } catch (error) {
    state.error = error.message;
  }
  render();
}

async function logout() {
  clearFeedback();
  try {
    await callBackend("Logout");
    state.session = {
      authenticated: false,
      token_present: false,
      user: null,
      server: null,
      passwords: [],
      notes: [],
    };
    state.selectedId = "";
    state.selectedItem = null;
    state.unlockedItem = null;
    state.activeTab = "passwords";
    state.message = "Logged out.";
  } catch (error) {
    state.error = error.message;
  }
  render();
}

async function selectPassword(id) {
  clearFeedback();
  state.selectedId = id;
  state.unlockedItem = null;
  try {
    state.selectedItem = await callBackend("GetPassword", id);
  } catch (error) {
    state.error = error.message;
  }
  render();
}

async function selectNote(id) {
  clearFeedback();
  state.selectedId = id;
  state.unlockedItem = null;
  try {
    state.selectedItem = await callBackend("GetNote", id);
  } catch (error) {
    state.error = error.message;
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
    state.error = error.message;
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
    state.error = error.message;
  }
  render();
}

function switchTab(tab) {
  if (state.activeTab === tab) return;
  clearFeedback();
  state.activeTab = tab;
  state.selectedId = "";
  state.selectedItem = null;
  state.unlockedItem = null;
  render();
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

hydrate();
