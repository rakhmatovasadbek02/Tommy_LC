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

// ── Guided tour: spotlights the real buttons (Vocab tab → unit picker → Start Practice,
// Support tab → day picker → a time slot → Profile tab) instead of just describing them.
// Multi-page — progress is persisted in localStorage so "Next" can navigate to the next
// page and pick the tour back up there. Shown once automatically on first Home load
// (lc_student_tutorial_seen), replayable anytime via the "?" button next to Sign Out.
const SP_TOUR_STEPS = [
  { page: 'student-portal.html', title: 'Welcome to Tommy LC!', body: "Quick tour — let's practice vocabulary and book a support session together." },
  { page: 'student-portal.html', selector: '#spTabbar a.sp-tab[href="student-vocab.html"]', title: 'Practice Vocabulary', body: 'Tap Vocab any time you want to practice — no teacher needed to start.' },
  { page: 'student-vocab.html', selector: '#unitList', title: 'Pick your units', body: 'Check one or more units you want to practice.' },
  { page: 'student-vocab.html', selector: '#startPracticeBtn', title: 'Start the quiz', body: 'Then tap Start Practice to begin. Results only save to your own history — no pressure.' },
  { page: 'student-vocab.html', selector: '#spTabbar a.sp-tab[href="student-support.html"]', title: 'Book a Support Session', body: 'Tap Support to book one-on-one time with a teacher.' },
  { page: 'student-support.html', selector: '.sp-day-tabs', fallbackSelector: '#bookCard', title: 'Choose a day', body: 'Pick Today, Tomorrow, or another day to see the open times.' },
  { page: 'student-support.html', selector: '.sp-slot-row', fallbackSelector: '#slotDays', title: 'Book a time', body: 'Tap any open time slot — you\'ll add a topic and confirm on the next two screens.' },
  { page: 'student-support.html', selector: '#spTabbar a.sp-tab[href="student-account.html"]', title: 'Your Profile', body: "That's it! Check the Profile tab anytime for your group, schedule, and details." },
];
function spTourSeen() { try { return !!localStorage.getItem('lc_student_tutorial_seen'); } catch { return true; } }
function spTourMarkSeen() { try { localStorage.setItem('lc_student_tutorial_seen', '1'); } catch {} }
function spTourActive() { try { return localStorage.getItem('lc_student_tour_active') === '1'; } catch { return false; } }
function spTourGetStep() { try { return parseInt(localStorage.getItem('lc_student_tour_step'), 10); } catch { return NaN; } }
function spTourSetStep(i) { try { localStorage.setItem('lc_student_tour_step', String(i)); localStorage.setItem('lc_student_tour_active', '1'); } catch {} }
function spCurrentPage() { return location.pathname.split('/').pop() || 'student-portal.html'; }

let _spTourCleanup = null; // removes the resize/scroll listeners tracking the current spotlighted element

function spTourClose(markSeen) {
  try { localStorage.removeItem('lc_student_tour_active'); } catch {}
  if (markSeen) spTourMarkSeen();
  if (_spTourCleanup) { _spTourCleanup(); _spTourCleanup = null; }
  const el = document.getElementById('spTourRoot');
  if (el) el.remove();
}

function spTourGoTo(i) {
  if (i < 0) return;
  if (i >= SP_TOUR_STEPS.length) { spTourClose(true); return; }
  spTourSetStep(i);
  const step = SP_TOUR_STEPS[i];
  if (step.page !== spCurrentPage()) { window.location.href = step.page; return; }
  spTourRenderStep(i);
}

// Called on load by every student page — a no-op unless a multi-page tour is mid-flight
// and this is the page its current step belongs on.
function spResumeTourIfActive() {
  if (!spTourActive()) return;
  const i = spTourGetStep();
  if (!Number.isInteger(i) || i < 0 || i >= SP_TOUR_STEPS.length) return;
  if (SP_TOUR_STEPS[i].page !== spCurrentPage()) return;
  spTourRenderStep(i);
}

function spStartTutorial() {
  spTourSetStep(0);
  if (spCurrentPage() !== SP_TOUR_STEPS[0].page) { window.location.href = SP_TOUR_STEPS[0].page; return; }
  spTourRenderStep(0);
}
// Auto-shown once on Home, a beat after the page's own content has rendered.
function spMaybeAutoStartTutorial() { if (!spTourSeen() && !spTourActive()) setTimeout(spStartTutorial, 500); }

function spTourRenderStep(i) {
  if (_spTourCleanup) { _spTourCleanup(); _spTourCleanup = null; }
  const old = document.getElementById('spTourRoot'); if (old) old.remove();
  const step = SP_TOUR_STEPS[i];
  const root = document.createElement('div');
  root.id = 'spTourRoot';
  document.body.appendChild(root);

  function actionsHtml() {
    const isLast = i === SP_TOUR_STEPS.length - 1;
    const dots = SP_TOUR_STEPS.map((_, n) => `<span class="sp-tour-dot${n === i ? ' on' : ''}"></span>`).join('');
    return `
      <div class="sp-tour-dots">${dots}</div>
      <div class="sp-tour-actions">
        <button class="sp-btn sp-btn-outline" id="spTourBack">${i > 0 ? 'Back' : 'Skip'}</button>
        <button class="sp-btn sp-btn-primary" id="spTourNext">${isLast ? 'Done' : 'Next'}</button>
      </div>`;
  }
  function bindActions() {
    document.getElementById('spTourNext').onclick = () => spTourGoTo(i + 1);
    document.getElementById('spTourBack').onclick = () => { if (i > 0) spTourGoTo(i - 1); else spTourClose(true); };
  }
  function positionCard(r) {
    const card = document.getElementById('spTourCard');
    if (!card) return;
    requestAnimationFrame(() => {
      const cw = card.offsetWidth, ch = card.offsetHeight, vw = window.innerWidth, vh = window.innerHeight;
      let top = r.bottom + 16;
      if (top + ch > vh - 16) top = Math.max(16, r.top - ch - 16);
      let left = r.left + r.width / 2 - cw / 2;
      left = Math.max(16, Math.min(left, vw - cw - 16));
      card.style.top = top + 'px';
      card.style.left = left + 'px';
    });
  }
  function draw(target) {
    if (!target) {
      root.innerHTML = `
        <div class="sp-tour-overlay sp-tour-center">
          <div class="sp-tour-card">
            <div class="sp-tour-title">${spEscapeHtml(step.title)}</div>
            <div class="sp-tour-body">${spEscapeHtml(step.body)}</div>
            ${actionsHtml()}
          </div>
        </div>`;
      bindActions();
      return;
    }
    const r = target.getBoundingClientRect();
    const pad = 8;
    root.innerHTML = `
      <div class="sp-tour-overlay"></div>
      <div class="sp-tour-hole" style="top:${r.top - pad}px;left:${r.left - pad}px;width:${r.width + pad * 2}px;height:${r.height + pad * 2}px;"></div>
      <div class="sp-tour-card sp-tour-pin" id="spTourCard">
        <div class="sp-tour-title">${spEscapeHtml(step.title)}</div>
        <div class="sp-tour-body">${spEscapeHtml(step.body)}</div>
        ${actionsHtml()}
      </div>`;
    bindActions();
    positionCard(r);
    const onReflow = () => {
      const el = document.querySelector(step.selector) || target;
      const nr = el.getBoundingClientRect();
      const hole = root.querySelector('.sp-tour-hole');
      if (hole) { hole.style.top = (nr.top - pad) + 'px'; hole.style.left = (nr.left - pad) + 'px'; hole.style.width = (nr.width + pad * 2) + 'px'; hole.style.height = (nr.height + pad * 2) + 'px'; }
      positionCard(nr);
    };
    window.addEventListener('resize', onReflow);
    window.addEventListener('scroll', onReflow, true);
    _spTourCleanup = () => { window.removeEventListener('resize', onReflow); window.removeEventListener('scroll', onReflow, true); };
  }

  // Async content (unit list, open slots) may not have rendered yet — poll briefly for
  // the target selector, falling back to a wider container, then to a plain centered card.
  function findTarget(attemptsLeft, cb) {
    if (!step.selector) return cb(null);
    const el = document.querySelector(step.selector);
    if (el) { el.scrollIntoView({ block: 'center' }); setTimeout(() => cb(el), 260); return; }
    if (attemptsLeft <= 0) {
      const fb = step.fallbackSelector && document.querySelector(step.fallbackSelector);
      if (fb) { fb.scrollIntoView({ block: 'center' }); setTimeout(() => cb(fb), 260); return; }
      return cb(null);
    }
    setTimeout(() => findTarget(attemptsLeft - 1, cb), 150);
  }
  findTarget(20, draw); // ~3s of polling
}

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
