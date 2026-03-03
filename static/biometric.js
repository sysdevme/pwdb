(() => {
  const HELPER = "http://127.0.0.1:9797";

  function isMacSafari() {
	const ua = navigator.userAgent;
	const isMac = ua.includes("Macintosh");
	const isSafari = ua.includes("Safari") && !ua.includes("Chrome") && !ua.includes("Chromium");
	return isMac && isSafari;
  }

  async function helperStatus() {
	try {
	  const r = await fetch(`${HELPER}/status`, { method: "GET" });
	  if (!r.ok) return { ok: false };
	  return await r.json();
	} catch {
	  return { ok: false };
	}
  }

  async function helperUnlock() {
	const r = await fetch(`${HELPER}/unlock`, {
	  method: "POST",
	  headers: { "Content-Type": "application/json" },
	  body: "{}",
	});
	const j = await r.json().catch(() => ({}));
	if (!r.ok || !j.token) throw new Error(j.error || "unlock failed");
	return j.token;
  }

  function ensureModal() {
	if (document.getElementById("pm-bio-modal")) return;

	document.body.insertAdjacentHTML("beforeend", `
<div class="modal" tabindex="-1" id="pm-bio-modal">
  <div class="modal-dialog modal-dialog-centered">
	<div class="modal-content">
	  <div class="modal-header">
		<h5 class="modal-title">Unlock</h5>
		<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
	  </div>
	  <div class="modal-body">
		<div id="pm-bio-error" class="alert alert-danger d-none"></div>
		<div>Touch ID / Face ID</div>
	  </div>
	  <div class="modal-footer">
		<button id="pm-bio-do" type="button" class="btn btn-primary">Unlock</button>
		<a href="/unlock" class="btn btn-outline-secondary">Use master password</a>
	  </div>
	</div>
  </div>
</div>
`);
  }

  function showModal() {
	ensureModal();
	const el = document.getElementById("pm-bio-modal");
	const modal = new bootstrap.Modal(el, { backdrop: "static", keyboard: false });
	modal.show();
	return modal;
  }

  function setError(msg) {
	const box = document.getElementById("pm-bio-error");
	if (!box) return;
	if (!msg) {
	  box.classList.add("d-none");
	  box.textContent = "";
	  return;
	}
	box.textContent = msg;
	box.classList.remove("d-none");
  }

  function submitBackendUnlock(token, next) {
	const form = document.getElementById("pm-bio-unlock-form");
	document.getElementById("pm-bio-token").value = token;
	document.getElementById("pm-bio-next").value = next || window.location.pathname + window.location.search;
	form.submit();
  }

  let bioAvailable = false;

  async function init() {
	if (!isMacSafari()) return;

	const st = await helperStatus();
	bioAvailable = !!(st && st.ok && st.biometrics);

	if (!bioAvailable) return;

	document.addEventListener("submit", async (e) => {
	  const form = e.target;
	  if (!(form instanceof HTMLFormElement)) return;

	  if (!form.hasAttribute("data-require-unlock")) return;

	  e.preventDefault();

	  const modal = showModal();
	  setError("");

	  const btn = document.getElementById("pm-bio-do");
	  btn.disabled = false;

	  btn.onclick = async () => {
		btn.disabled = true;
		setError("");
		try {
		  const token = await helperUnlock();
		  modal.hide();
		  submitBackendUnlock(token, window.location.pathname + window.location.search);
		} catch (err) {
		  btn.disabled = false;
		  setError(err?.message || String(err));
		}
	  };
	});
  }

  document.addEventListener("DOMContentLoaded", init);
})();