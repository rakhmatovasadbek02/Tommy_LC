// ══════════════════════════════════════════
// Tommy LC CRM — Shared Utilities (PostgreSQL)
// ══════════════════════════════════════════

const API = '';

function authHeaders(extra) {
 const h = extra || {};
 try {
   const s = JSON.parse(sessionStorage.getItem('lc_session') || localStorage.getItem('lc_session') || 'null');
   if (s && s.token) h['Authorization'] = 'Bearer ' + s.token;
 } catch {}
 return h;
}
async function handleRes(r, path) {
 if (r.status === 401 && !String(path).includes('/auth/login')) {
   sessionStorage.removeItem('lc_session'); localStorage.removeItem('lc_session');
   window.location.replace('login.html');
   throw new Error('Session expired — please sign in again.');
 }
 if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.error || r.statusText); }
 return r.json();
}
async function apiGet(path) {
 return handleRes(await fetch(API + path, { headers: authHeaders() }), path);
}
async function apiPost(path, data) {
 return handleRes(await fetch(API + path, { method:'POST', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify(data) }), path);
}
async function apiPut(path, data) {
 return handleRes(await fetch(API + path, { method:'PUT', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify(data) }), path);
}
async function apiPatch(path, data) {
 return handleRes(await fetch(API + path, { method:'PATCH', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify(data) }), path);
}
async function apiDelete(path, body) {
 const opts = { method:'DELETE', headers: authHeaders() };
 if (body) { opts.headers = authHeaders({'Content-Type':'application/json'}); opts.body = JSON.stringify(body); }
 return handleRes(await fetch(API + path, opts), path);
}

function genId() {
 return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

/* ══════════════════════════════════════
   i18n — English / Русский / Oʻzbek
══════════════════════════════════════ */
const LANGS = { en:{name:'English',flag:'🇬🇧'}, ru:{name:'Русский',flag:'🇷🇺'}, uz:{name:"Oʻzbek",flag:'🇺🇿'} };
function getLang(){ try { return localStorage.getItem('lc_lang') || 'en'; } catch { return 'en'; } }
function setLang(l){ try { localStorage.setItem('lc_lang', l); } catch {} location.reload(); }

const I18N = {
 ru: {
  "Dashboard":"Главная","Leads":"Лиды","Students":"Студенты","Groups":"Группы","Finance":"Финансы",
  "Teachers":"Учителя","Staff":"Персонал","Actions":"Действия","Classrooms":"Кабинеты","Archived":"Архив",
  "Learning Center":"Учебный центр","Sign Out":"Выйти","Search students…":"Поиск студентов…","Search…":"Поиск…",
  "Welcome back":"С возвращением","Sign in to continue":"Войдите, чтобы продолжить","Phone Number":"Номер телефона",
  "Password":"Пароль","Sign In →":"Войти →","Are you the creator?":"Вы создатель?","Sign in":"Войти",
  "Active Students":"Активные студенты","currently enrolled":"сейчас зачислены","Debtors":"Должники",
  "negative balance":"отрицательный баланс","Paid":"Оплачено","invoices settled":"оплаченные счета","Leads ":"Лиды ",
  "in pipeline":"в воронке","Trial":"Пробный","on trial period":"на пробном периоде","Absent Today":"Отсутствуют сегодня",
  "not in class today":"нет на занятии","Timetable":"Расписание","Odd Days":"Нечётные дни","Even Days":"Чётные дни",
  "Custom":"Свои","All Groups":"Все группы","Classroom":"Кабинет",
  "Add New":"Добавить","Add Student":"Добавить студента","Add Group":"Добавить группу","Add Staff":"Добавить сотрудника",
  "New Payment":"Новый платёж","Export":"Экспорт","Register Lead":"Зарегистрировать лида","Add":"Добавить",
  "Save":"Сохранить","Save Payment":"Сохранить платёж","Save Group":"Сохранить группу","Cancel":"Отмена",
  "Edit":"Изменить","Delete":"Удалить","Close":"Закрыть","Levels":"Уровни","Save Prices":"Сохранить цены",
  "First Name":"Имя","Last Name":"Фамилия","Phone":"Телефон","Role":"Роль","Name":"Имя","Status":"Статус",
  "Level":"Уровень","Active":"Активный","Inactive":"Неактивный","Notes":"Заметки","Comments":"Комментарии",
  "All Levels":"Все уровни","All Statuses":"Все статусы","All Types":"Все типы","Payments":"Платежи",
  "Phone *":"Телефон *","First Name *":"Имя *","Last Name *":"Фамилия *","Role *":"Роль *","Student *":"Студент *",
  "Group":"Группа","Test Result":"Результат теста","Current Level":"Текущий уровень","Address":"Адрес","Grade":"Класс","School":"Школа",
  "balance":"баланс","Attendance":"Посещаемость","Exams":"Экзамены","History":"История","Save Attendance":"Сохранить",
  "Back":"Назад","Profile":"Профиль","Activate":"Активировать","Waitlist":"Лист ожидания","Registration":"Регистрация",
  "Outstanding Debt":"Задолженность","Revenue":"Доход","Expected Monthly":"Ожидаемо в месяц","All-Time Revenue":"Доход за всё время",
  "Job title":"Должность","Job title *":"Должность *","Settings":"Настройки",
  "Good morning":"Доброе утро","Good afternoon":"Добрый день","Good evening":"Добрый вечер",
  "Here's what's happening at Tommy Learning Center today.":"Вот что происходит в Tommy Learning Center сегодня."
 },
 uz: {
  "Dashboard":"Asosiy","Leads":"Lidlar","Students":"Oʻquvchilar","Groups":"Guruhlar","Finance":"Moliya",
  "Teachers":"Oʻqituvchilar","Staff":"Xodimlar","Actions":"Amallar","Classrooms":"Sinflar","Archived":"Arxiv",
  "Learning Center":"Oʻquv markazi","Sign Out":"Chiqish","Search students…":"Oʻquvchilarni qidirish…","Search…":"Qidirish…",
  "Welcome back":"Xush kelibsiz","Sign in to continue":"Davom etish uchun kiring","Phone Number":"Telefon raqami",
  "Password":"Parol","Sign In →":"Kirish →","Are you the creator?":"Siz yaratuvchimisiz?","Sign in":"Kirish",
  "Active Students":"Faol oʻquvchilar","currently enrolled":"hozir oʻqiydi","Debtors":"Qarzdorlar",
  "negative balance":"manfiy balans","Paid":"Toʻlangan","invoices settled":"toʻlangan toʻlovlar","Leads ":"Lidlar ",
  "in pipeline":"jarayonda","Trial":"Sinov","on trial period":"sinov muddatida","Absent Today":"Bugun yoʻq",
  "not in class today":"bugun darsda yoʻq","Timetable":"Dars jadvali","Odd Days":"Toq kunlar","Even Days":"Juft kunlar",
  "Custom":"Maxsus","All Groups":"Barcha guruhlar","Classroom":"Sinf",
  "Add New":"Qoʻshish","Add Student":"Oʻquvchi qoʻshish","Add Group":"Guruh qoʻshish","Add Staff":"Xodim qoʻshish",
  "New Payment":"Yangi toʻlov","Export":"Eksport","Register Lead":"Lid qoʻshish","Add":"Qoʻshish",
  "Save":"Saqlash","Save Payment":"Toʻlovni saqlash","Save Group":"Guruhni saqlash","Cancel":"Bekor qilish",
  "Edit":"Tahrirlash","Delete":"Oʻchirish","Close":"Yopish","Levels":"Darajalar","Save Prices":"Narxlarni saqlash",
  "First Name":"Ism","Last Name":"Familiya","Phone":"Telefon","Role":"Rol","Name":"Ism","Status":"Holat",
  "Level":"Daraja","Active":"Faol","Inactive":"Nofaol","Notes":"Izohlar","Comments":"Izohlar",
  "All Levels":"Barcha darajalar","All Statuses":"Barcha holatlar","All Types":"Barcha turlar","Payments":"Toʻlovlar",
  "Phone *":"Telefon *","First Name *":"Ism *","Last Name *":"Familiya *","Role *":"Rol *","Student *":"Oʻquvchi *",
  "Group":"Guruh","Test Result":"Test natijasi","Current Level":"Joriy daraja","Address":"Manzil","Grade":"Sinf","School":"Maktab",
  "balance":"balans","Attendance":"Davomat","Exams":"Imtihonlar","History":"Tarix","Save Attendance":"Saqlash",
  "Back":"Orqaga","Profile":"Profil","Activate":"Faollashtirish","Waitlist":"Navbat","Registration":"Roʻyxat",
  "Outstanding Debt":"Qarzdorlik","Revenue":"Daromad","Expected Monthly":"Oylik kutilgan","All-Time Revenue":"Umumiy daromad",
  "Job title":"Lavozim","Job title *":"Lavozim *","Settings":"Sozlamalar",
  "Good morning":"Xayrli tong","Good afternoon":"Xayrli kun","Good evening":"Xayrli kech",
  "Here's what's happening at Tommy Learning Center today.":"Bugun Tommy Learning Center'da nimalar bo'layotganini ko'ring."
 }
};
function t(s){ const l=getLang(); if(l==='en'||s==null) return s; const d=I18N[l]; const k=String(s).trim(); return (d && d[k]!=null) ? d[k] : s; }

function translateAll(root){
 const l=getLang(); if(l==='en') return; const d=I18N[l]; if(!d) return;
 const walker=document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
 const nodes=[]; while(walker.nextNode()) nodes.push(walker.currentNode);
 nodes.forEach(n=>{ const raw=n.nodeValue; const key=raw.trim(); if(key && d[key]!=null) n.nodeValue = raw.replace(key, d[key]); });
 (root.querySelectorAll?root.querySelectorAll('[placeholder]'):[]).forEach(e=>{ const k=e.getAttribute('placeholder').trim(); if(d[k]!=null) e.setAttribute('placeholder', d[k]); });
}
let _i18nObserver=null;
function startI18nObserver(){
 if(_i18nObserver || getLang()==='en') return;
 _i18nObserver=new MutationObserver(muts=>{
  muts.forEach(m=>m.addedNodes.forEach(n=>{
   if(n.nodeType===1) translateAll(n);
   else if(n.nodeType===3){ const d=I18N[getLang()]; const k=(n.nodeValue||'').trim(); if(d&&d[k]!=null) n.nodeValue=n.nodeValue.replace(k,d[k]); }
  }));
 });
 _i18nObserver.observe(document.body,{childList:true,subtree:true});
}
function initI18n(){ try{ translateAll(document.body); startI18nObserver(); }catch{} }
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', initI18n); else initI18n();

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

// Page permissions (page = see + manage), plus the finance view-only modifier.
const PAGE_PERMISSIONS = ['dashboard','leads','students','groups','finance','teachers','staff','actions','archived','reminders'];
const ALL_PERMISSIONS = [...PAGE_PERMISSIONS, 'finance_view_only'];
// Sidebar/page feature keys that differ from permission keys.
const PERM_ALIAS = { payments:'finance', settings:'staff' };

function isTeacher() { const s = getSession(); const roles = s && s.roles || [s && s.title || '']; return roles.some(r => String(r).trim().toLowerCase() === 'teacher'); }
function isSupportTeacher() { const s = getSession(); const roles = s && s.roles || [s && s.title || '']; return roles.some(r => String(r).trim().toLowerCase() === 'support teacher'); }
function isAdministration() { const s = getSession(); const roles = s && s.roles || [s && s.title || '']; const adm = ['ceo','head admin','manager','admin']; return roles.some(r => adm.includes(String(r).trim().toLowerCase())); }
function canManageFinance() { return can('finance') && !getPermissions().includes('finance_view_only'); }
// For teacher accounts, a group is "own" when its assigned teacher matches the user's name.
function ownsGroup(g) { const s = getSession(); return !isTeacher() ? true : String(g && g.teacher || '') === (s && s.name || ''); }

function getSession() {
 try { return JSON.parse(sessionStorage.getItem('lc_session') || localStorage.getItem('lc_session') || 'null'); }
 catch { return null; }
}
function setSession(data) {
 const s = JSON.stringify(data);
 sessionStorage.setItem('lc_session', s);
 localStorage.setItem('lc_session', s);
}
function getRole() { const s = getSession(); return s ? (s.title || s.role) : null; }
function getPermissions() { const s = getSession(); return (s && Array.isArray(s.permissions)) ? s.permissions : []; }
const UNIVERSAL_FEATURES = ['reminders'];
function can(feature) {
 if (UNIVERSAL_FEATURES.includes(feature) && getSession()) return true;
 const perms = getPermissions();
 const key = PERM_ALIAS[feature] || feature;
 return perms.includes(key);
}

function requireAuth(requiredFeature) {
 const session = getSession();
 // No session, or a stale session from before tokens existed → force a clean re-login.
 if (!session || !session.token) {
 sessionStorage.removeItem('lc_session'); localStorage.removeItem('lc_session');
 window.location.replace('login.html'); return;
 }
 if (requiredFeature && !can(requiredFeature)) {
 sessionStorage.setItem('lc_access_denied', requiredFeature);
 // Send them to the first section they CAN open. If none, the account is unusable → sign out.
 const fallback = ['dashboard','students','groups','leads','finance','staff','actions','archived']
   .find(f => can(f));
 const pageFor = { dashboard:'index.html', students:'students.html', groups:'groups.html', leads:'leads.html',
   finance:'finance.html', staff:'users.html', actions:'actions.html',
   archived:'archived.html' };
 if (fallback) window.location.replace(pageFor[fallback]);
 else { sessionStorage.removeItem('lc_session'); localStorage.removeItem('lc_session'); window.location.replace('login.html'); }
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
 const labels = { payments:'Finance', finance:'Finance', teachers:'Teachers', settings:'Staff', staff:'Staff', groups:'Groups', leads:'Leads', students:'Students', actions:'Actions', archived:'Archived', dashboard:'Dashboard' };
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
 actions: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
 archived: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`,
 support: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
 reminders: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
};

const IC = {
 plus: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
 edit: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
 trash: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
 search: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
 close: `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
 check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
 arrowRight: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`,
 arrowUp: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>`,
 arrowDown: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>`,
 arrowLeft: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>`,
 refresh: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`,
 logout: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
 reminders: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
};

function renderSidebar(activePage) {
 const session = getSession();
 if (!session) return;

 const hasBothRoles = isTeacher() && isSupportTeacher();
 const NAV_SECTIONS = [
 { label: null, items: [
   { feature:'dashboard', href:'index.html',      iconKey:'dashboard', label: hasBothRoles ? 'Teaching' : 'Dashboard' },
   { feature:'leads',     href:'leads.html',      iconKey:'leads',     label:'Leads'      },
   { feature:'support',   href:'support.html',    iconKey:'support',   label:'Support'    },
   { feature:'reminders', href:'reminders.html',  iconKey:'reminders', label:'To Do List' },
   { feature:'students',  href:'students.html',   iconKey:'students',  label:'Students'   },
   { feature:'groups',    href:'groups.html',     iconKey:'groups',    label:'Groups'     },
   { feature:'payments',  href:'finance.html',    iconKey:'payments',  label:'Finance'    },
   { feature:'settings',  href:'users.html',      iconKey:'settings',  label:'Staff'      },
   { feature:'archived',  href:'archived.html',   iconKey:'archived',  label:'Archived'   },
   { feature:'actions',   href:'actions.html',    iconKey:'actions',   label:'Actions'    },
 ]},
 ];

 const meta = { color: avatarColor(session.name||'?'), badge: 'badge-grey' };
 const roleLabel = (session.roles && session.roles.length > 1) ? session.roles.join(' · ') : (session.title || session.role || 'Staff');
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
 <a href="index.html" class="sidebar-brand" style="text-decoration:none;display:flex;align-items:center;gap:11px;">
 <img src="logo.png" width="36" height="36" alt="" style="flex-shrink:0;display:block">
 <div>
 <div class="brand-name">Tommy LC</div>
 <div class="brand-sub">Learning Center</div>
 </div>
 </a>
 ${navHTML}
 <div class="sidebar-footer">
 <div class="user-pill" style="margin-bottom:10px">
 <div class="user-avatar" style="background:${meta.color}">${session.avatar||initials(session.name)}</div>
 <div class="user-info">
 <div class="user-name">${session.name}</div>
 <div class="user-role"><span class="badge ${meta.badge}" style="font-size:9px;padding:1px 7px">${roleLabel}</span></div>
 </div>
 </div>
 <button onclick="logout()" style="width:100%;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.10);color:rgba(255,255,255,0.50);border-radius:8px;padding:8px 12px;font-size:12px;font-weight:500;cursor:pointer;font-family:'Inter',sans-serif;transition:all 0.14s;display:flex;align-items:center;justify-content:center;gap:7px;" onmouseover="this.style.background='rgba(255,255,255,0.12)';this.style.color='rgba(255,255,255,0.88)'" onmouseout="this.style.background='rgba(255,255,255,0.06)';this.style.color='rgba(255,255,255,0.50)'">
 ${IC.logout} Sign Out
 </button>
 </div>`;

 const sidebar = document.querySelector('.sidebar');
 if (sidebar) { sidebar.innerHTML = sidebarHTML; translateAll(sidebar); }

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

 injectReminderBell();
 injectLangSwitcher();
 injectFooter();
 checkAccessDeniedMessage();
}

function injectReminderBell() {
 if (document.getElementById('notifBtn')) return;
 let tr = document.querySelector('.topbar-right');
 if (!tr) { tr = document.createElement('div'); tr.className = 'topbar-right'; document.querySelector('.topbar')?.appendChild(tr); }
 if (!tr) return;

 // Inject panel styles once
 if (!document.getElementById('notifStyles')) {
  const s = document.createElement('style');
  s.id = 'notifStyles';
  s.textContent = `
   #notifWrap { position:relative; flex-shrink:0; }
   #notifBtn { display:inline-flex;align-items:center;gap:6px;padding:0 12px;height:34px;border-radius:8px;background:var(--bg,#f5f5f5);color:var(--text,#222);font-size:12px;font-weight:600;font-family:inherit;border:1px solid var(--border,#e0e0e0);cursor:pointer;transition:background .14s;position:relative; }
   #notifBtn:hover { background:var(--border,#e8eaee); }
   #notifBadge { display:none;background:#e74c3c;color:#fff;font-size:10px;font-weight:700;border-radius:20px;min-width:18px;height:18px;line-height:18px;text-align:center;padding:0 4px; }
   #notifPanel { display:none;position:absolute;top:calc(100% + 8px);right:0;width:340px;background:#fff;border:1px solid var(--border,#e0e0e0);border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.12);z-index:1000;overflow:hidden; }
   #notifPanel.open { display:block; }
   .notif-panel-head { display:flex;align-items:center;justify-content:space-between;padding:14px 16px 10px;border-bottom:1px solid var(--border,#e8eaee); }
   .notif-panel-head span { font-size:14px;font-weight:700;color:var(--text,#222); }
   .notif-mark-all { font-size:11px;color:#3b5bdb;cursor:pointer;background:none;border:none;font-weight:600;padding:0; }
   .notif-mark-all:hover { text-decoration:underline; }
   .notif-list { max-height:380px;overflow-y:auto; }
   .notif-empty { text-align:center;padding:32px 16px;color:#999;font-size:13px; }
   .notif-item { display:flex;gap:12px;padding:12px 16px;cursor:pointer;transition:background .1s;border-bottom:1px solid var(--border,#f0f0f0); }
   .notif-item:last-child { border-bottom:none; }
   .notif-item:hover { background:#f8f9fa; }
   .notif-item.unread { background:#f0f4ff; }
   .notif-item.unread:hover { background:#e8eeff; }
   .notif-icon { width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0; }
   .notif-icon.task_assigned { background:#e8f5e9; }
   .notif-icon.task_status  { background:#fff3e0; }
   .notif-icon.new_student  { background:#e8eeff; }
   .notif-icon.new_lead     { background:#f5f0ff; }
   .notif-icon.payment      { background:#e8f5e9; }
   .notif-text { flex:1;min-width:0; }
   .notif-title { font-size:13px;font-weight:600;color:var(--text,#222);line-height:1.3; }
   .notif-body  { font-size:12px;color:#666;margin-top:2px;line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis; }
   .notif-time  { font-size:10px;color:#aaa;margin-top:4px; }
   .notif-dot   { width:7px;height:7px;border-radius:50%;background:#3b5bdb;flex-shrink:0;margin-top:5px; }
   .notif-footer { padding:10px 16px;border-top:1px solid var(--border,#e8eaee);text-align:center; }
   .notif-footer a { font-size:12px;color:#3b5bdb;font-weight:600;text-decoration:none; }
   .notif-footer a:hover { text-decoration:underline; }
  `;
  document.head.appendChild(s);
 }

 const wrap = document.createElement('div');
 wrap.id = 'notifWrap';
 wrap.innerHTML = `
  <button id="notifBtn" onclick="toggleNotifPanel(event)">
   <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
   <span>Notifications</span>
   <span id="notifBadge"></span>
  </button>
  <div id="notifPanel">
   <div class="notif-panel-head">
    <span>Notifications</span>
    <button class="notif-mark-all" onclick="markAllNotifsRead()">Mark all as read</button>
   </div>
   <div class="notif-list" id="notifList"><div class="notif-empty">Loading…</div></div>
   <div class="notif-footer"><a href="reminders.html">View To Do List →</a></div>
  </div>`;
 tr.appendChild(wrap);

 document.addEventListener('click', e => {
  if (!e.target.closest('#notifWrap')) document.getElementById('notifPanel')?.classList.remove('open');
 });
 refreshNotifCount();
}

const NOTIF_ICONS = { task_assigned:'📋', task_status:'🔄', new_student:'👤', new_lead:'🎯', payment:'💰' };

function toggleNotifPanel(e) {
 e.stopPropagation();
 const panel = document.getElementById('notifPanel');
 if (!panel) return;
 const opening = !panel.classList.contains('open');
 panel.classList.toggle('open');
 if (opening) loadNotifPanel();
}

function loadNotifPanel() {
 const list = document.getElementById('notifList');
 if (!list) return;
 apiGet('/api/notifications').then(items => {
  if (!items.length) { list.innerHTML = '<div class="notif-empty">No notifications yet</div>'; return; }
  list.innerHTML = items.map(n => {
   const icon = NOTIF_ICONS[n.type] || '🔔';
   const age = notifAge(n.createdAt);
   return `<div class="notif-item${n.read ? '' : ' unread'}" onclick="openNotif('${n.id}','${n.link||''}')">
    <div class="notif-icon ${n.type}">${icon}</div>
    <div class="notif-text">
     <div class="notif-title">${n.title}</div>
     ${n.body ? `<div class="notif-body">${n.body}</div>` : ''}
     <div class="notif-time">${age}</div>
    </div>
    ${n.read ? '' : '<div class="notif-dot"></div>'}
   </div>`;
  }).join('');
  refreshNotifCount();
 }).catch(() => { if (list) list.innerHTML = '<div class="notif-empty">Could not load</div>'; });
}

function notifAge(ts) {
 const d = Math.floor((Date.now() - new Date(ts)) / 1000);
 if (d < 60) return 'Just now';
 if (d < 3600) return Math.floor(d/60) + 'm ago';
 if (d < 86400) return Math.floor(d/3600) + 'h ago';
 return Math.floor(d/86400) + 'd ago';
}

function openNotif(id, link) {
 apiPut(`/api/notifications/${id}/read`, {}).catch(()=>{});
 if (link) window.location.href = link;
 else document.getElementById('notifPanel')?.classList.remove('open');
}

function markAllNotifsRead() {
 apiPut('/api/notifications/read-all', {}).then(() => {
  loadNotifPanel();
  refreshNotifCount();
 }).catch(()=>{});
}

function refreshNotifCount() {
 apiGet('/api/notifications/count').then(d => {
  const badge = document.getElementById('notifBadge');
  if (!badge) return;
  if (d.count > 0) { badge.textContent = d.count > 99 ? '99+' : d.count; badge.style.display = 'inline-block'; }
  else badge.style.display = 'none';
 }).catch(() => {});
}

function refreshReminderCount() { refreshNotifCount(); }

function injectFooter() {
 const main = document.querySelector('.main');
 if (!main || document.getElementById('appFooter')) return;
 const f = document.createElement('footer');
 f.id = 'appFooter'; f.className = 'app-footer';
 f.innerHTML = `<span>© ${new Date().getFullYear()} Raxmatovs Family LLC</span>`
   + `<span class="sep">·</span><span>📞 +998 90 404 24 68</span>`
   + `<span class="sep">·</span><span>📍 Sirdaryo city, Uzbekistan str 150</span>`;
 main.appendChild(f);
}

function injectLangSwitcher() {
 if (document.getElementById('langDd')) return;
 let tr = document.querySelector('.topbar-right');
 if (!tr) {
   tr = document.createElement('div');
   tr.className = 'topbar-right';
   document.querySelector('.topbar')?.appendChild(tr);
 }
 if (!tr) return;
 const cur = LANGS[getLang()] || LANGS.en;
 const dd = document.createElement('div');
 dd.className = 'lang-dd'; dd.id = 'langDd';
 dd.innerHTML = `<button class="lang-dd-btn" onclick="toggleLangDd(event)" title="Language">${cur.flag}</button>
 <div class="lang-dd-menu" id="langDdMenu">${Object.entries(LANGS).map(([c,o])=>`<button class="lang-dd-item${getLang()===c?' active':''}" onclick="setLang('${c}')"><span class="flag">${o.flag}</span>${o.name}</button>`).join('')}</div>`;
 tr.appendChild(dd);
}
function toggleLangDd(e) { e.stopPropagation(); document.getElementById('langDdMenu')?.classList.toggle('open'); }
document.addEventListener('click', e => { const m=document.getElementById('langDdMenu'); if (m && !e.target.closest('#langDd')) m.classList.remove('open'); });

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