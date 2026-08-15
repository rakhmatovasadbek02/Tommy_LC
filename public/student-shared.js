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

// ── First-time tour: a short step-through overlay introducing each tab. Shown once
// automatically (tracked per-browser via localStorage), and replayable anytime via the
// "?" button next to Sign Out in the header.
const SP_TOUR_STEPS = [
  { icon: 'fa-hand-sparkles', title: 'Welcome to Tommy LC!', body: "Here's a quick look at what you can do in your student portal." },
  { icon: 'fa-house', title: 'Home', body: "See what's coming up next, your vocabulary stats, and a unit recommended just for you." },
  { icon: 'fa-lightbulb', title: 'Vocab', body: 'Practice any unit whenever you like. Practice results only save to your own history — no pressure.' },
  { icon: 'fa-comments', title: 'Support', body: 'Book one free support session a day with a teacher, at a time that works for you.' },
  { icon: 'fa-user', title: 'Profile', body: 'Check your group, schedule, and contact details. Ask your admin if anything needs to change.' },
];
function spTourSeen() { try { return !!localStorage.getItem('lc_student_tutorial_seen'); } catch { return true; } }
function spTourMarkSeen() { try { localStorage.setItem('lc_student_tutorial_seen', '1'); } catch {} }
function spStartTutorial() {
  let idx = 0;
  const overlay = document.createElement('div');
  overlay.className = 'sp-tour-overlay';
  document.body.appendChild(overlay);
  function close() { spTourMarkSeen(); overlay.remove(); }
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  function render() {
    const step = SP_TOUR_STEPS[idx];
    const isLast = idx === SP_TOUR_STEPS.length - 1;
    overlay.innerHTML = `
      <div class="sp-tour-card">
        <div class="sp-tour-icon"><i class="fas ${step.icon}"></i></div>
        <div class="sp-tour-title">${spEscapeHtml(step.title)}</div>
        <div class="sp-tour-body">${spEscapeHtml(step.body)}</div>
        <div class="sp-tour-dots">${SP_TOUR_STEPS.map((_, i) => `<span class="sp-tour-dot${i === idx ? ' on' : ''}"></span>`).join('')}</div>
        <div class="sp-tour-actions">
          <button class="sp-btn sp-btn-outline" id="spTourBack">${idx > 0 ? 'Back' : 'Skip'}</button>
          <button class="sp-btn sp-btn-primary" id="spTourNext">${isLast ? 'Get Started' : 'Next'}</button>
        </div>
      </div>`;
    document.getElementById('spTourNext').onclick = () => { if (isLast) close(); else { idx++; render(); } };
    document.getElementById('spTourBack').onclick = () => { if (idx > 0) { idx--; render(); } else close(); };
  }
  render();
}
// Auto-shown once on Home, a beat after the page's own content has rendered.
function spMaybeAutoStartTutorial() { if (!spTourSeen()) setTimeout(spStartTutorial, 500); }

function spInitials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] || '') + (parts[1]?.[0] || '')).toUpperCase() || '?';
}

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

// Renders the lightweight top bar (brand + sign out) into #spHeader, if present, and the
// bottom tab bar — the app's primary section navigation — into #spTabbar, if present.
// Split in two (rather than one combined header) to match the "Tommy LC Student App"
// design: a slim brand bar up top, navigation as an app-style tab bar at the bottom.
function spRenderHeader(activeKey) {
  const top = document.getElementById('spHeader');
  if (top) {
    const s = spGetSession();
    top.innerHTML = `
      <div class="sp-header-inner">
        <a href="student-portal.html" class="sp-brand">
          <img class="sp-brand-mark" src="logo.png" alt="Tommy LC">
          <span class="sp-brand-text">Tommy LC</span>
        </a>
        <div class="sp-header-right">
          <span class="sp-header-name">${spEscapeHtml(s ? s.name : '')}</span>
          <button class="sp-logout-btn" onclick="spStartTutorial()" title="Take the tour"><i class="fas fa-circle-question"></i></button>
          <button class="sp-logout-btn" onclick="spLogout()" title="Sign out"><i class="fas fa-arrow-right-from-bracket"></i></button>
        </div>
      </div>`;
  }
  const tabs = document.getElementById('spTabbar');
  if (tabs) {
    const items = [
      { key: 'home', href: 'student-portal.html', icon: 'fa-house', label: 'Home' },
      { key: 'profile', href: 'student-account.html', icon: 'fa-user', label: 'Profile' },
      { key: 'vocab', href: 'student-vocab.html', icon: 'fa-lightbulb', label: 'Vocab' },
      { key: 'support', href: 'student-support.html', icon: 'fa-comments', label: 'Support' },
    ];
    tabs.innerHTML = `
      <div class="sp-tabbar-inner">
        ${items.map(it => `<a href="${it.href}" class="sp-tab${activeKey===it.key?' on':''}"><i class="fas ${it.icon}"></i>${it.label}</a>`).join('')}
      </div>`;
  }
}
