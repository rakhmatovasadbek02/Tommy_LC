// ══════════════════════════════════════════
// Tommy LC CRM — Shared Utilities (PostgreSQL)
// ══════════════════════════════════════════

const API = '';

async function apiGet(path) {
 const r = await fetch(API + path);
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}
async function apiPost(path, data) {
 const r = await fetch(API + path, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}
async function apiPut(path, data) {
 const r = await fetch(API + path, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}
async function apiPatch(path, data) {
 const r = await fetch(API + path, { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}
async function apiDelete(path) {
 const r = await fetch(API + path, { method:'DELETE' });
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}

function genId() {
 return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function formatCurrency(n) { return '$' + Number(n || 0).toFixed(2); }
function formatDate(iso) {
 if (!iso) return '—';
 return new Date(iso).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}

const AVATAR_COLORS = ['#FF0000','#1D4ED8','#1E6B45','#7C3AED','#A05C00','#0891B2','#BE185D','#D97706'];
function avatarColor(name) {
 let h = 0;
 for (let c of (name||'?')) h = (h<<5)-h+c.charCodeAt(0);
 return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length];
}
function initials(name) {
 return (name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
}

const ROLE_PERMISSIONS = { 'CEO': '*' };
const ROLE_META = {
 'CEO':     { color:'#FF0000', badge:'badge-red',  label:'CEO'     },
 'Teacher': { color:'#1D4ED8', badge:'badge-blue', label:'Teacher' },
 'Admin':   { color:'#1E6B45', badge:'badge-green',label:'Admin'   },
};

function getSession() {
 try { return JSON.parse(sessionStorage.getItem('lc_session') || localStorage.getItem('lc_session') || 'null'); }
 catch { return null; }
}
function setSession(data) {
 const s = JSON.stringify(data);
 sessionStorage.setItem('lc_session', s);
 localStorage.setItem('lc_session', s);
}
function getRole() { const s = getSession(); return s ? s.role : null; }
function can(feature) {
 const role = getRole();
 if (!role) return false;
 if (role === 'CEO') return true;
 const perms = ROLE_PERMISSIONS[role];
 return Array.isArray(perms) && perms.includes(feature);
}

function requireAuth(requiredFeature) {
 const session = getSession();
 if (!session) { window.location.replace('login.html'); return; }
 if (requiredFeature && session.role !== 'CEO' && !can(requiredFeature)) {
 sessionStorage.setItem('lc_access_denied', requiredFeature);
 window.location.replace('index.html');
 }
}
function logout() {
 sessionStorage.removeItem('lc_session');
 localStorage.removeItem('lc_session');
 window.location.replace('login.html');
}

function logActivity(text, color) {
 const session = getSession();
 apiPost('/api/activity', {
 text, color: color||'',
 actor: session?.name || 'System',
 role: session?.role || ''
 }).catch(() => {});
}

function showToast(message, type) {
 const container = document.getElementById('toastContainer');
 if (!container) return;
 const toast = document.createElement('div');
 toast.className = 'toast ' + (type||'success');
 toast.innerHTML = message;
 container.appendChild(toast);
 setTimeout(() => toast.remove(), 3500);
}

function checkAccessDeniedMessage() {
 const denied = sessionStorage.getItem('lc_access_denied');
 if (denied) {
 sessionStorage.removeItem('lc_access_denied');
 const labels = { payments:'Payments', teachers:'Teachers', settings:'Staff', groups:'Groups', classrooms:'Classrooms', leads:'Leads', students:'Students' };
 showToast(`Your role does not have access to ${labels[denied]||denied}.`, 'error');
 }
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.addEventListener('click', e => {
 if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('open');
});

const NAV_ICONS = {
 dashboard: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>`,
 leads: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`,
 students: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
 groups: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`,
 payments: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>`,
 teachers: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>`,
 classrooms: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`,
 settings: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M12 2v2M12 20v2M20 12h2M2 12h2M17.66 17.66l1.41 1.41M4.93 19.07l1.41-1.41"/></svg>`,
};

const IC = {
 plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
 edit: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
 trash: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
 search: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
 close: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
 check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
 arrowRight: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`,
 arrowLeft: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>`,
 refresh: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
 logout: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
};

function renderSidebar(activePage) {
 const session = getSession();
 if (!session) return;

 const NAV_SECTIONS = [
 { label: null, items: [
   { feature:'dashboard', href:'index.html',    iconKey:'dashboard', label:'Dashboard' },
   { feature:'leads',     href:'leads.html',    iconKey:'leads',     label:'Leads'     },
   { feature:'students',  href:'students.html', iconKey:'students',  label:'Students'  },
   { feature:'groups',    href:'groups.html',   iconKey:'groups',    label:'Groups'    },
   { feature:'payments',  href:'finance.html',  iconKey:'payments',  label:'Finance'   },
 ]},
 { label: 'Staff', items: [
   { feature:'teachers', href:'teachers.html', iconKey:'teachers', label:'Teachers' },
   { feature:'settings', href:'users.html',    iconKey:'settings',  label:'Staff'    },
 ]},
 { label: 'Settings', items: [
   { feature:'classrooms', href:'classrooms.html', iconKey:'classrooms', label:'Classrooms' },
 ]},
 ];

 const meta = ROLE_META[session.role] || ROLE_META['CEO'];
 const navHTML = NAV_SECTIONS.map(section => {
   const links = section.items
     .filter(item => can(item.feature))
     .map(item => {
       const isActive = item.feature === activePage;
       return `<a href="${item.href}" class="nav-link${isActive?' active':''}"><span class="icon">${NAV_ICONS[item.iconKey]||''}</span>${item.label}</a>`;
     }).join('');
   if (!links) return '';
   return `<div class="nav-section">
     ${section.label ? `<div class="nav-label">${section.label}</div>` : ''}
     ${links}
   </div>`;
 }).join('');

 const sidebarHTML = `
 <a href="index.html" class="sidebar-brand" style="text-decoration:none;display:block;">
 <div class="brand-name">Tommy LC</div>
 <div class="brand-sub">Learning Center</div>
 </a>
 ${navHTML}
 <div class="sidebar-footer">
 <div class="user-pill" style="margin-bottom:10px">
 <div class="user-avatar" style="background:${meta.color}">${session.avatar||initials(session.name)}</div>
 <div class="user-info">
 <div class="user-name">${session.name}</div>
 <div class="user-role"><span class="badge ${meta.badge}" style="font-size:9px;padding:1px 7px">${session.role}</span></div>
 </div>
 </div>
 <button onclick="logout()" style="width:100%;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);color:rgba(255,255,255,0.50);border-radius:8px;padding:8px 12px;font-size:12px;font-weight:500;cursor:pointer;font-family:'Inter',sans-serif;transition:all 0.14s;display:flex;align-items:center;justify-content:center;gap:7px;" onmouseover="this.style.background='rgba(255,255,255,0.12)';this.style.color='rgba(255,255,255,0.88)'" onmouseout="this.style.background='rgba(255,255,255,0.06)';this.style.color='rgba(255,255,255,0.50)'">
 ${IC.logout} Sign Out
 </button>
 </div>`;

 const sidebar = document.querySelector('.sidebar');
 if (sidebar) sidebar.innerHTML = sidebarHTML;

 const topbar = document.querySelector('.topbar');
 if (topbar && !document.getElementById('menuToggle')) {
 const toggle = document.createElement('button');
 toggle.id = 'menuToggle';
 toggle.className = 'menu-toggle';
 toggle.innerHTML = '<span></span><span></span><span></span>';
 toggle.onclick = toggleSidebar;
 topbar.insertBefore(toggle, topbar.firstChild);
 }
 if (!document.getElementById('sidebarOverlay')) {
 const overlay = document.createElement('div');
 overlay.id = 'sidebarOverlay';
 overlay.className = 'sidebar-overlay';
 overlay.onclick = closeSidebar;
 document.body.appendChild(overlay);
 }

 checkAccessDeniedMessage();
}

function toggleSidebar() {
 const s = document.querySelector('.sidebar');
 const o = document.getElementById('sidebarOverlay');
 const open = s?.classList.contains('open');
 s?.classList.toggle('open', !open);
 o?.classList.toggle('show', !open);
}
function closeSidebar() {
 document.querySelector('.sidebar')?.classList.remove('open');
 document.getElementById('sidebarOverlay')?.classList.remove('show');
}
document.addEventListener('click', e => {
 if (e.target.closest('.nav-link') && window.innerWidth <= 640) closeSidebar();
});