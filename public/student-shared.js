// ══════════════════════════════════════════
// Tommy LC — Student Portal shared helpers
// Deliberately separate from shared.js (staff app): a different session storage key
// (lc_student_session) so a student's login can never collide with a staff login in the
// same browser, and no dependency on the staff nav/permission system.
// ══════════════════════════════════════════
const SP_API = '';

function spGetSession() {
  try { return JSON.parse(localStorage.getItem('lc_student_session') || 'null'); } catch { return null; }
}
function spSetSession(data) {
  try { localStorage.setItem('lc_student_session', JSON.stringify(data)); } catch {}
}
function spLogout() {
  try { localStorage.removeItem('lc_student_session'); } catch {}
  window.location.replace('student-login.html');
}
function spRequireAuth() {
  if (!spGetSession()) { window.location.replace('student-login.html'); throw new Error('redirect'); }
}
function spAuthHeaders(extra) {
  const h = extra || {};
  const s = spGetSession();
  if (s && s.token) h['Authorization'] = 'Bearer ' + s.token;
  return h;
}
async function spHandleRes(r) {
  if (r.status === 401) { spLogout(); throw new Error('Session expired — please sign in again.'); }
  if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
  return r.json();
}
async function spGet(path) {
  return spHandleRes(await fetch(SP_API + path, { headers: spAuthHeaders() }));
}
async function spPost(path, data) {
  return spHandleRes(await fetch(SP_API + path, { method:'POST', headers: spAuthHeaders({'Content-Type':'application/json'}), body: JSON.stringify(data||{}) }));
}

function spEscapeHtml(s) { return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function spToast(message, type) {
  let box = document.getElementById('spToastContainer');
  if (!box) { box = document.createElement('div'); box.id = 'spToastContainer'; box.className = 'sp-toast-container'; document.body.appendChild(box); }
  const t = document.createElement('div');
  t.className = 'sp-toast' + (type === 'error' ? ' sp-toast-error' : '');
  t.textContent = message;
  box.appendChild(t);
  setTimeout(() => t.classList.add('show'), 10);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 250); }, 3200);
}

// Renders the shared top header (logo + student name + logout) into #spHeader, if present.
function spRenderHeader(activeKey) {
  const el = document.getElementById('spHeader');
  if (!el) return;
  const s = spGetSession();
  el.innerHTML = `
    <div class="sp-header-inner">
      <a href="student-portal.html" class="sp-brand">
        <img class="sp-brand-mark" src="logo.png" alt="Tommy LC">
        <span class="sp-brand-text">Tommy<b>LC</b><span>Student Portal</span></span>
      </a>
      <nav class="sp-nav">
        <a href="student-portal.html" class="${activeKey==='home'?'on':''}">Profile</a>
        <a href="student-vocab.html" class="${activeKey==='vocab'?'on':''}">Vocabulary</a>
        <a href="student-support.html" class="${activeKey==='support'?'on':''}">Support</a>
      </nav>
      <div class="sp-header-right">
        <span class="sp-header-name">${spEscapeHtml(s ? s.name : '')}</span>
        <button class="sp-logout-btn" onclick="spLogout()">Sign out</button>
      </div>
    </div>`;
}
