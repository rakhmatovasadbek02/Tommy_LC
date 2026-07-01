const express  = require('express');
const { Pool } = require('pg');
const path     = require('path');
const cors     = require('cors');
const cron     = require('node-cron');
const crypto   = require('crypto');
const compression = require('compression');

const app  = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// SSE live-update clients
const sseClients = new Set();
function broadcast(type) {
  const msg = `data: ${JSON.stringify({ type })}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch { sseClients.delete(res); }
  }
}

app.use(compression());
app.use(cors());
app.use(express.json());

/* ══════════════════════════════════════
   PERMISSIONS
══════════════════════════════════════ */
// Page permissions: having one = full see + manage of that section.
const PAGE_PERMISSIONS = ['dashboard','leads','students','groups','finance','teachers','staff','actions','archived','support'];
// finance_view_only restricts Finance to read (no recording/editing).
const ALL_PERMISSIONS = [...PAGE_PERMISSIONS, 'finance_view_only'];

// Fixed roles → permission sets. These are the only assignable titles.
const ROLE_PERMS = {
  'CEO':        [...PAGE_PERMISSIONS, 'statistics', 'manreminders'],
  'Head Admin': ['dashboard','leads','students','groups','teachers','staff','archived','reminders'],
  'Manager':    ['dashboard','leads','students','groups','finance','teachers','staff','archived','reminders','manreminders'],
  'Admin':      ['dashboard','leads','students','groups','teachers','reminders'],
  'Teacher':    ['dashboard','groups','reminders'],
  'Support Teacher': ['dashboard','support','reminders'],
};
function isSupportTitle(t) { return String(t||'').trim().toLowerCase() === 'support teacher'; }
const ROLES = Object.keys(ROLE_PERMS);
function permsForRole(title) { return (ROLE_PERMS[title] || ['dashboard']).slice(); }
function permsForRoles(roles) {
  const set = new Set();
  (roles||[]).forEach(r => (ROLE_PERMS[r]||[]).forEach(p => set.add(p)));
  if (!set.size) set.add('dashboard');
  return [...set];
}
function isTeacherTitle(t) { return String(t||'').trim().toLowerCase() === 'teacher'; }

// Password rules. Creation: at least 8 digits (repetition allowed).
function validateCreatePassword(pw) {
  if (((String(pw||'').match(/\d/g))||[]).length < 8) return 'Password must contain at least 8 digits.';
  return null;
}
// First-login change: at least 8 digits, not all the same, not sequential, not too simple.
function validateNewPassword(pw) {
  const digits = String(pw||'').replace(/\D/g, '');
  if (digits.length < 8) return 'Password must contain at least 8 digits.';
  if (new Set(digits.split('')).size < 3) return 'Too simple — use at least 3 different digits.';
  let up = true, down = true;
  for (let i = 1; i < digits.length; i++) {
    if (+digits[i] !== +digits[i-1] + 1) up = false;
    if (+digits[i] !== +digits[i-1] - 1) down = false;
  }
  if (up || down) return 'Too simple — avoid sequential numbers.';
  return null;
}

/* ══════════════════════════════════════
   AUTH TOKENS  (HMAC-signed identity token)
══════════════════════════════════════ */
let APP_SECRET = null;
async function loadAppSecret() {
  if (process.env.APP_SECRET) { APP_SECRET = process.env.APP_SECRET; return; }
  const r = await pool.query(`SELECT value FROM app_config WHERE key='auth_secret'`);
  if (r.rows[0]) { APP_SECRET = r.rows[0].value; return; }
  APP_SECRET = crypto.randomBytes(32).toString('hex');
  await pool.query(`INSERT INTO app_config(key,value) VALUES('auth_secret',$1) ON CONFLICT(key) DO NOTHING`, [APP_SECRET]);
  const check = await pool.query(`SELECT value FROM app_config WHERE key='auth_secret'`);
  if (check.rows[0]) APP_SECRET = check.rows[0].value;
}
function signToken(userId) {
  const sig = crypto.createHmac('sha256', APP_SECRET).update(String(userId)).digest('hex');
  return Buffer.from(userId + '.' + sig).toString('base64');
}
function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const idx = decoded.lastIndexOf('.');
    if (idx < 0) return null;
    const userId = decoded.slice(0, idx), sig = decoded.slice(idx + 1);
    const expected = crypto.createHmac('sha256', APP_SECRET).update(userId).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    return userId;
  } catch { return null; }
}

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  setHeaders(res, fp) {
    // Fonts/images rarely change → cache hard. HTML/CSS/JS → revalidate (ETag) so deploys show instantly.
    if (/sw\.js$/.test(fp)) res.setHeader('Cache-Control', 'no-cache');
    else if (/\.(woff2?|ttf|png|jpg|jpeg|svg|ico)$/.test(fp)) res.setHeader('Cache-Control', 'public, max-age=86400');
    else res.setHeader('Cache-Control', 'no-cache');
  }
}));

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      first_name  TEXT NOT NULL,
      last_name   TEXT NOT NULL,
      phone       TEXT NOT NULL UNIQUE,
      password    TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'Admin',
      avatar      TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS students (
      id          TEXT PRIMARY KEY,
      first_name  TEXT NOT NULL,
      last_name   TEXT NOT NULL,
      phone       TEXT,
      phone_parent TEXT,
      level       TEXT,
      status      TEXT DEFAULT 'Active',
      balance     NUMERIC DEFAULT 0,
      exam        TEXT,
      exam_date   DATE,
      notes       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS student_comments (
      id          SERIAL PRIMARY KEY,
      student_id  TEXT NOT NULL,
      text        TEXT NOT NULL,
      actor       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS student_calls (
      id          SERIAL PRIMARY KEY,
      student_id  TEXT NOT NULL,
      note        TEXT NOT NULL,
      actor       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS teachers (
      id          TEXT PRIMARY KEY,
      first_name  TEXT NOT NULL,
      last_name   TEXT NOT NULL,
      phone       TEXT,
      password    TEXT,
      status      TEXT DEFAULT 'Active',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reminders (
      id            TEXT PRIMARY KEY,
      title         TEXT NOT NULL,
      note          TEXT,
      due_date      DATE,
      due_time      TIME,
      priority      TEXT DEFAULT 'medium',
      created_by_id TEXT NOT NULL,
      assigned_to_id TEXT NOT NULL,
      done          BOOLEAN DEFAULT FALSE,
      status        TEXT DEFAULT 'pending',
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE reminders ADD COLUMN IF NOT EXISTS due_time TIME;
    ALTER TABLE reminders ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';
    ALTER TABLE reminders ADD COLUMN IF NOT EXISTS repeat_every TEXT DEFAULT NULL;
    -- Migrate existing done=true rows to completed
    UPDATE reminders SET status='completed' WHERE done=TRUE AND (status IS NULL OR status='pending');
    -- Auto-mark overdue: past due date+time and not completed
    UPDATE reminders SET status='overdue'
      WHERE status IN ('pending','in_process')
        AND due_date IS NOT NULL
        AND (due_date + COALESCE(due_time, '23:59:59'::time)) < NOW() AT TIME ZONE 'Asia/Tashkent';

    CREATE TABLE IF NOT EXISTS notifications (
      id          TEXT PRIMARY KEY,
      recipient_id TEXT NOT NULL,
      type        TEXT NOT NULL,
      title       TEXT NOT NULL,
      body        TEXT,
      link        TEXT,
      read        BOOLEAN DEFAULT FALSE,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS groups (
      id           TEXT PRIMARY KEY,
      name         TEXT NOT NULL,
      teacher      TEXT,
      room         TEXT,
      level        TEXT,
      lang         TEXT DEFAULT 'UZ',
      max_students INTEGER,
      sched_type   TEXT DEFAULT 'odd',
      custom_days  JSONB DEFAULT '[]',
      time         TEXT,
      duration     INTEGER DEFAULT 90,
      start_date   DATE,
      notes        TEXT,
      student_ids  JSONB DEFAULT '[]',
      current_unit TEXT DEFAULT '1A',
      price        NUMERIC DEFAULT 0,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS custom_levels (
      level TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pricing (
      level       TEXT PRIMARY KEY,
      price       NUMERIC NOT NULL DEFAULT 0,
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    );

    INSERT INTO pricing (level, price) VALUES
      ('RoundUp', 0),('Beginner', 0),('Elementary', 0),
      ('Pre-Intermediate', 0),('Intermediate', 0),('CEFR', 0),('IELTS', 0)
    ON CONFLICT DO NOTHING;

    CREATE TABLE IF NOT EXISTS invoices (
      id           TEXT PRIMARY KEY,
      number       TEXT,
      student_id   TEXT,
      group_id     TEXT,
      level        TEXT,
      month        TEXT,
      description  TEXT,
      total        NUMERIC DEFAULT 0,
      due_date     DATE,
      status       TEXT DEFAULT 'Pending',
      payment_type TEXT DEFAULT 'Cash',
      notes        TEXT,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id          SERIAL PRIMARY KEY,
      group_id    TEXT NOT NULL,
      date        DATE NOT NULL,
      student_id  TEXT NOT NULL,
      status      TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(group_id, date, student_id)
    );

    CREATE TABLE IF NOT EXISTS leads (
      id            TEXT PRIMARY KEY,
      first_name    TEXT NOT NULL,
      last_name     TEXT NOT NULL,
      phone_student TEXT,
      phone_father  TEXT,
      phone_mother  TEXT,
      phone_other   TEXT,
      current_level TEXT,
      test_result   TEXT,
      status        TEXT DEFAULT 'Registration',
      group_id      TEXT,
      is_trial      BOOLEAN DEFAULT FALSE,
      notes         TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS group_comments (
      id          SERIAL PRIMARY KEY,
      group_id    TEXT NOT NULL,
      text        TEXT NOT NULL,
      actor       TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity (
      id          SERIAL PRIMARY KEY,
      text        TEXT NOT NULL,
      color       TEXT,
      actor       TEXT,
      role        TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Safe ALTER TABLE calls — only add missing columns
  const alters = [
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS lang         TEXT DEFAULT 'UZ'`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS current_unit TEXT DEFAULT '1A'`,
    `ALTER TABLE groups ADD COLUMN IF NOT EXISTS price        NUMERIC DEFAULT 0`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS group_id     TEXT`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS level        TEXT`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS month        TEXT`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS payment_type TEXT DEFAULT 'Cash'`,
    `ALTER TABLE invoices ADD COLUMN IF NOT EXISTS creator      TEXT`,
    `ALTER TABLE teachers ADD COLUMN IF NOT EXISTS password TEXT`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS sub_container TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS balance NUMERIC DEFAULT 0`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS balance_frozen BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS frozen_comment TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_parent TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_mother TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_other  TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS archive_reason TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS school TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS grade TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS address TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '[]'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS title TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_start TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_end TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_days TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_odd_start TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_odd_end TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_even_start TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_even_end TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS roles JSONB DEFAULT '[]'`,
    `ALTER TABLE support_sessions ADD COLUMN IF NOT EXISTS attended BOOLEAN`,
    `ALTER TABLE support_sessions ADD COLUMN IF NOT EXISTS theme TEXT`,
    `CREATE TABLE IF NOT EXISTS support_fines (id TEXT PRIMARY KEY, student_id TEXT NOT NULL, issued_at TIMESTAMPTZ DEFAULT NOW(), blocked_until TIMESTAMPTZ NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)`,
    `CREATE TABLE IF NOT EXISTS support_sessions (id TEXT PRIMARY KEY, date DATE, time TEXT, duration INT DEFAULT 30, teacher TEXT, student_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_invoices_student ON invoices(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_comments_student ON student_comments(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_calls_student ON student_calls(student_id)`,
    `CREATE TABLE IF NOT EXISTS lead_calls (id SERIAL PRIMARY KEY, lead_id TEXT NOT NULL, note TEXT NOT NULL, actor TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_lead_calls ON lead_calls(lead_id)`,
    `CREATE TABLE IF NOT EXISTS lead_conversions (id SERIAL PRIMARY KEY, lead_id TEXT NOT NULL, student_id TEXT, converted_by TEXT, converted_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_attendance_grp_date ON attendance(group_id, date)`,
    `CREATE INDEX IF NOT EXISTS idx_groups_student_ids ON groups USING gin (student_ids)`,
    `CREATE TABLE IF NOT EXISTS archive_reasons (id SERIAL PRIMARY KEY, label TEXT NOT NULL UNIQUE, is_blacklist BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS archive_comment TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS pre_archive_status TEXT`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS archive_reason TEXT`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS archive_comment TEXT`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS pre_archive_status TEXT`,
    `CREATE TABLE IF NOT EXISTS spendings (
      id TEXT PRIMARY KEY,
      amount NUMERIC NOT NULL,
      category TEXT,
      description TEXT,
      month TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
  ];
  for (const sql of alters) {
    await pool.query(sql).catch(() => {});
  }

  // Grant 'statistics' permission to all existing CEO users who don't have it yet.
  try {
    const ceos = await pool.query(`SELECT id, permissions FROM users WHERE title='CEO' OR roles @> '["CEO"]'::jsonb`);
    for (const u of ceos.rows) {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      if (!perms.includes('statistics')) {
        await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify([...perms,'statistics']), u.id]);
      }
    }
  } catch(e) { console.warn('Statistics permission migration skipped:', e.message); }

  // Grant 'manreminders' to existing CEO and Manager users.
  try {
    const mgrs = await pool.query(`SELECT id, permissions FROM users WHERE title IN ('CEO','Manager') OR roles @> '["CEO"]'::jsonb OR roles @> '["Manager"]'::jsonb`);
    for (const u of mgrs.rows) {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      if (!perms.includes('manreminders')) {
        await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify([...perms,'manreminders']), u.id]);
      }
    }
  } catch(e) { console.warn('manreminders permission migration skipped:', e.message); }

  // Strip 'finance' and 'finance_view_only' from all Head Admin accounts.
  try {
    const headAdmins = await pool.query(`SELECT id, permissions FROM users WHERE title='Head Admin' OR roles @> '["Head Admin"]'::jsonb`);
    for (const u of headAdmins.rows) {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      if (perms.includes('finance') || perms.includes('finance_view_only')) {
        await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(perms.filter(p => p !== 'finance' && p !== 'finance_view_only')), u.id]);
      }
    }
  } catch(e) { console.warn('Head Admin finance-permission strip skipped:', e.message); }

  // Strip 'students' permission from all Teacher accounts (teachers access students via group page only).
  try {
    const teachers = await pool.query(`SELECT id, permissions FROM users WHERE title='Teacher' OR roles @> '["Teacher"]'::jsonb`);
    for (const u of teachers.rows) {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      if (perms.includes('students')) {
        await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(perms.filter(p => p !== 'students')), u.id]);
      }
    }
  } catch(e) { console.warn('Teacher students-permission strip skipped:', e.message); }

  // One-time: migrate old single support shift → separate odd/even shifts.
  try {
    await pool.query(`
      UPDATE users SET
        support_odd_start  = CASE WHEN COALESCE(support_days,'daily') IN ('odd','daily')  THEN COALESCE(support_start,'09:00') END,
        support_odd_end    = CASE WHEN COALESCE(support_days,'daily') IN ('odd','daily')  THEN COALESCE(support_end,'18:00')  END,
        support_even_start = CASE WHEN COALESCE(support_days,'daily') IN ('even','daily') THEN COALESCE(support_start,'09:00') END,
        support_even_end   = CASE WHEN COALESCE(support_days,'daily') IN ('even','daily') THEN COALESCE(support_end,'18:00')  END
      WHERE title='Support Teacher' AND support_odd_start IS NULL AND support_even_start IS NULL`);
  } catch(e) { console.warn('Support shift migration skipped:', e.message); }

  // One-time migration: give existing users a permission list derived from their old role.
  // Runs only for users whose permissions are still empty (NULL or []).
  try {
    // Permissions are derived from the user's fixed role (title, falling back to role column).
    const all = await pool.query('SELECT id, role, title FROM users');
    for (const u of all.rows) {
      const roleName = ROLE_PERMS[u.title] ? u.title : (ROLE_PERMS[u.role] ? u.role : 'Admin');
      await pool.query('UPDATE users SET permissions=$1, title=$2, role=$2 WHERE id=$3',
        [JSON.stringify(permsForRole(roleName)), roleName, u.id]);
    }
  } catch(e) { console.warn('Permission migration skipped:', e.message); }

  // Re-sync permissions from roles[] for all users (runs every startup to pick up new role perms).
  try {
    const all = await pool.query('SELECT id, roles, title FROM users');
    for (const u of all.rows) {
      const roles = Array.isArray(u.roles) && u.roles.length ? u.roles : [u.title||'Admin'];
      const perms = permsForRoles(roles);
      await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(perms), u.id]);
    }
  } catch(e) { console.warn('Permissions re-sync skipped:', e.message); }

  // One-time migration: populate roles[] from title for existing users.
  try {
    await pool.query(`UPDATE users SET roles=$1 WHERE roles IS NULL OR roles='[]'::jsonb`, [JSON.stringify([])]);
    const all = await pool.query('SELECT id, title FROM users WHERE roles=\'[]\'::jsonb OR roles IS NULL');
    for (const u of all.rows) {
      const t = ROLE_PERMS[u.title] ? u.title : 'Admin';
      await pool.query('UPDATE users SET roles=$1 WHERE id=$2', [JSON.stringify([t]), u.id]);
    }
  } catch(e) { console.warn('Roles migration skipped:', e.message); }

  // Remove trial lead IDs from group student_ids (they should never be in there)
  try {
    const trialLeads = await pool.query(`SELECT id FROM leads WHERE status='Trial'`);
    const trialIds = new Set(trialLeads.rows.map(r => r.id));
    if (trialIds.size > 0) {
      const grps = await pool.query('SELECT id, student_ids FROM groups');
      for (const grp of grps.rows) {
        const ids = grp.student_ids || [];
        const cleaned = ids.filter(id => !trialIds.has(id));
        if (cleaned.length !== ids.length) {
          await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(cleaned), grp.id]);
          console.log(`Cleaned trial IDs from group ${grp.id}: ${ids.length} -> ${cleaned.length}`);
        }
      }
    }
  } catch(e) { console.warn('Trial cleanup skipped:', e.message); }

  // Merge legacy teachers into staff (users) as 'Teacher' accounts, then drain the table.
  try {
    const ts = await pool.query('SELECT * FROM teachers');
    for (const t of ts.rows) {
      const phone = t.phone || ('temp-'+t.id);
      const dup = await pool.query("SELECT 1 FROM users WHERE REPLACE(phone,' ','')=REPLACE($1,' ','') LIMIT 1", [phone]);
      let ok = dup.rows.length > 0;
      if (!ok) {
        const avatar = ((t.first_name||'?')[0]+((t.last_name||'')[0]||'')).toUpperCase();
        try {
          await pool.query(
            "INSERT INTO users(id,first_name,last_name,phone,password,role,title,avatar,permissions,must_change_password) VALUES($1,$2,$3,$4,$5,'Teacher','Teacher',$6,$7,TRUE)",
            [t.id, t.first_name, t.last_name, phone, t.password||'00000000', avatar, JSON.stringify(ROLE_PERMS['Teacher'])]
          );
          ok = true;
        } catch(e) { ok = false; }
      }
      if (ok) await pool.query('DELETE FROM teachers WHERE id=$1', [t.id]);
    }
  } catch(e) { console.warn('Teacher→staff merge skipped:', e.message); }

  // Null out group teacher names that no longer match a Teacher staff member
  try {
    await pool.query(`
      UPDATE groups SET teacher = NULL
      WHERE teacher IS NOT NULL
      AND teacher NOT IN (SELECT first_name || ' ' || last_name FROM users WHERE title='Teacher')
    `);
  } catch(e) { console.warn('Teacher orphan cleanup skipped:', e.message); }

  // Remove previously seeded 101e data
  try {
    const seedIds = ['seed_101e_s01','seed_101e_s02','seed_101e_s03','seed_101e_s04','seed_101e_s05',
      'seed_101e_s06','seed_101e_s07','seed_101e_s08','seed_101e_s09','seed_101e_s10',
      'seed_101e_s11','seed_101e_s12','seed_101e_s13','seed_101e_s14','seed_101e_s15',
      'seed_101e_s16','seed_101e_s17','seed_101e_s18'];
    await pool.query(`DELETE FROM students WHERE id = ANY($1)`, [seedIds]);
    await pool.query(`DELETE FROM groups WHERE id = 'seed_grp_101e'`);
    await pool.query(`DELETE FROM teachers WHERE id = 'seed_raxmatov_asadbek'`);
  } catch(e) { console.warn('Seed cleanup skipped:', e.message); }

  const { rows } = await pool.query('SELECT COUNT(*) FROM users');
  if (parseInt(rows[0].count) === 0) {
    await pool.query(
      `INSERT INTO users (id, first_name, last_name, phone, password, role, avatar, title, permissions)
       VALUES ('u1','Admin','TommyLC','90 000 00 01','admin123','CEO','AT','CEO',$1)
       ON CONFLICT DO NOTHING`,
      [JSON.stringify(ROLE_PERMS['CEO'])]
    );
    console.log('Seeded default CEO: phone=90 000 00 01  password=admin123');
  }

  // Grant 'reminders' to all existing users who don't have it yet
  await pool.query(`
    UPDATE users SET permissions = permissions || '["reminders"]'::jsonb
    WHERE NOT (permissions @> '["reminders"]'::jsonb)
  `).catch(() => {});

  await loadAppSecret();
  console.log('Database ready');
}

// Notification helpers
async function createNotif(recipientId, type, title, body, link) {
  const id = 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2,6);
  await pool.query(
    `INSERT INTO notifications(id,recipient_id,type,title,body,link) VALUES($1,$2,$3,$4,$5,$6)`,
    [id, recipientId, type, title, body||null, link||null]
  ).catch(()=>{});
}

async function notifyRole(perm, type, title, body, link, excludeId) {
  const { rows } = await pool.query(
    `SELECT id FROM users WHERE permissions @> $1::jsonb${excludeId ? ' AND id<>$2' : ''}`,
    excludeId ? [JSON.stringify([perm]), excludeId] : [JSON.stringify([perm])]
  ).catch(()=>({rows:[]}));
  for (const u of rows) await createNotif(u.id, type, title, body, link);
}

/* ══════════════════════════════════════
   AUTH MIDDLEWARE — gate every /api route
══════════════════════════════════════ */
// Page permission a write requires (page perm = see + manage). null = any logged-in user.
// Reads stay open except the sensitive staff list + activity log.
function requiredPerm(method, p) {
  const seg = p.split('/').filter(Boolean);
  const top = seg[0];
  const write = method !== 'GET';

  if (top === 'auth') return null;
  if (top === 'activity') return method === 'GET' ? 'actions' : null;
  if (top === 'users') return write ? 'staff' : 'staff';

  if (top === 'students') {
    if (seg[2] === 'payment')  return 'finance';
    if (seg[2] === 'comments' || seg[2] === 'calls') return null;
    if (seg[1] === 'comments' || seg[1] === 'calls') return null;
    if (write) return 'students';
    return null;
  }
  if (top === 'groups') {
    if (seg[2] === 'comments' || seg[1] === 'comments') return null;
    if (write) return 'groups';
    return null;
  }
  if (top === 'invoices')   return write ? 'finance'    : null;
  if (top === 'teachers')   return write ? 'teachers'   : null;
  if (top === 'leads')      return write ? 'leads'      : null;
  if (top === 'pricing')    return write ? 'finance'    : null;
  if (top === 'levels')     return write ? 'groups'     : null;
  if (top === 'attendance') return write ? 'groups'     : null;
  if (top === 'support')    return write ? 'groups'     : null;
  if (top === 'admin')      return 'finance';
  return null;
}

// Finance write routes — blocked when the user is finance view-only.
function isFinanceWrite(method, p) {
  if (method === 'GET') return false;
  const seg = p.split('/').filter(Boolean);
  if (seg[0] === 'invoices' || seg[0] === 'pricing' || seg[0] === 'admin') return true;
  if (seg[0] === 'students' && seg[2] === 'payment') return true;
  return false;
}

app.use('/api', async (req, res, next) => {
  try {
    if (req.path.startsWith('/auth/')) return next();
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : (req.headers['x-auth-token'] || req.query.token || '');
    const userId = token && verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Not authenticated' });
    const r = await pool.query('SELECT id, first_name, last_name, role, title, roles, permissions FROM users WHERE id=$1', [userId]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Session no longer valid' });
    req.user = r.rows[0];
    const perms = req.user.permissions || [];
    const p = req.path.replace(/^\//, '');
    const write = req.method !== 'GET';
    const top = p.split('/').filter(Boolean)[0];

    // Pure Teacher accounts (Teacher is their only role): read-only everywhere; only attendance,
    // activity log, and their own account (e.g. first-login password change) may be written.
    const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
    const isPureTeacher = userRoles.every(r => isTeacherTitle(r));
    if (isPureTeacher) {
      if (write && top !== 'attendance' && top !== 'activity' && top !== 'account') {
        return res.status(403).json({ error: 'Teachers can only mark attendance.' });
      }
      return next();
    }
    // Finance view-only: block finance writes.
    if (isFinanceWrite(req.method, p) && perms.includes('finance_view_only')) {
      return res.status(403).json({ error: 'Your Finance access is view-only.' });
    }
    const need = requiredPerm(req.method, p);
    if (need && !perms.includes(need)) {
      return res.status(403).json({ error: 'You do not have permission for this action.' });
    }
    next();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  sseClients.add(res);
  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(hb); sseClients.delete(res); }
  }, 25000);
  req.on('close', () => { clearInterval(hb); sseClients.delete(res); });
});

/* AUTH */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM users WHERE REPLACE(phone,' ','')=$1 AND password=$2`,
      [phone.replace(/\s/g,''), password]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const u = rows[0];
    res.json({
      id: u.id, name: u.first_name+' '+u.last_name,
      role: u.role, title: u.title || u.role, avatar: u.avatar, phone: u.phone,
      roles: Array.isArray(u.roles) && u.roles.length ? u.roles : [u.title || u.role],
      permissions: u.permissions || [],
      mustChangePassword: !!u.must_change_password,
      token: signToken(u.id)
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Force-change password (first login). Authenticated via token (middleware sets req.user).
app.post('/api/account/change-password', async (req, res) => {
  try {
    const err = validateNewPassword(req.body.newPassword);
    if (err) return res.status(400).json({ error: err });
    await pool.query('UPDATE users SET password=$1, must_change_password=FALSE WHERE id=$2', [req.body.newPassword, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* USERS */
function cleanPerms(permissions) {
  return Array.isArray(permissions) ? permissions.filter(p => ALL_PERMISSIONS.includes(p)) : [];
}
// Support-teacher shifts (separate odd/even), only meaningful for Support Teacher.
// A null start means the teacher does NOT work that day type.
function supportShift(body, title) {
  if (!isSupportTitle(title)) return { oddStart:null, oddEnd:null, evenStart:null, evenEnd:null };
  const v = t => /^\d{2}:\d{2}$/.test(t) ? t : null;
  return {
    oddStart:  body.oddStart  ? v(body.oddStart)  : null,
    oddEnd:    body.oddStart  ? (v(body.oddEnd)  || '18:00') : null,
    evenStart: body.evenStart ? v(body.evenStart) : null,
    evenEnd:   body.evenStart ? (v(body.evenEnd) || '18:00') : null,
  };
}

app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at');
    res.json(rows.map(u => ({
      id: u.id, firstName: u.first_name, lastName: u.last_name,
      name: u.first_name+' '+u.last_name, phone: u.phone,
      role: u.role, title: u.title || u.role, avatar: u.avatar,
      roles: Array.isArray(u.roles) && u.roles.length ? u.roles : [u.title || u.role],
      permissions: u.permissions || [],
      oddStart: u.support_odd_start, oddEnd: u.support_odd_end,
      evenStart: u.support_even_start, evenEnd: u.support_even_end
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

const HEAD_ADMIN_ALLOWED = ['Teacher','Support Teacher','Admin'];
function callerRoles(req) { return Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title]; }
function isHeadAdminOnly(req) { const r = callerRoles(req); return r.includes('Head Admin') && !r.includes('CEO'); }
function headAdminCanTarget(targetRoles) { return targetRoles.every(r => HEAD_ADMIN_ALLOWED.includes(r)); }

app.post('/api/users', async (req, res) => {
  try {
    const { id, firstName, lastName, phone, password } = req.body;
    const roles = Array.isArray(req.body.roles) && req.body.roles.length ? req.body.roles : [req.body.title];
    if (!roles.every(r => ROLE_PERMS[r])) return res.status(400).json({ error: 'Invalid role' });
    if (isHeadAdminOnly(req) && !headAdminCanTarget(roles)) return res.status(403).json({ error: 'Head Admin can only create Teacher, Support Teacher, or Admin accounts.' });
    const title = roles[0];
    const pwErr = validateCreatePassword(password);
    if (pwErr) return res.status(400).json({ error: pwErr });
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    const perms = permsForRoles(roles);
    const sh = supportShift(req.body, roles.includes('Support Teacher') ? 'Support Teacher' : title);
    await pool.query(
      'INSERT INTO users(id,first_name,last_name,phone,password,role,title,roles,avatar,permissions,must_change_password,support_odd_start,support_odd_end,support_even_start,support_even_end) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,$11,$12,$13,$14)',
      [id, firstName, lastName, phone, password, title, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd]
    );
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, password } = req.body;
    const roles = Array.isArray(req.body.roles) && req.body.roles.length ? req.body.roles : [req.body.title];
    if (!roles.every(r => ROLE_PERMS[r])) return res.status(400).json({ error: 'Invalid role' });
    if (isHeadAdminOnly(req)) {
      const target = await pool.query('SELECT roles, title FROM users WHERE id=$1', [req.params.id]);
      const targetRoles = target.rows[0] ? (Array.isArray(target.rows[0].roles) && target.rows[0].roles.length ? target.rows[0].roles : [target.rows[0].title]) : [];
      if (!headAdminCanTarget(targetRoles) || !headAdminCanTarget(roles)) return res.status(403).json({ error: 'Head Admin can only manage Teacher, Support Teacher, or Admin accounts.' });
    }
    const title = roles[0];
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    const perms = permsForRoles(roles);
    const sh = supportShift(req.body, roles.includes('Support Teacher') ? 'Support Teacher' : title);
    if (password) {
      const pwErr = validateCreatePassword(password);
      if (pwErr) return res.status(400).json({ error: pwErr });
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,password=$4,role=$5,title=$5,roles=$6,avatar=$7,permissions=$8,must_change_password=TRUE,support_odd_start=$9,support_odd_end=$10,support_even_start=$11,support_even_end=$12 WHERE id=$13',
        [firstName, lastName, phone, password, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,role=$4,title=$4,roles=$5,avatar=$6,permissions=$7,support_odd_start=$8,support_odd_end=$9,support_even_start=$10,support_even_end=$11 WHERE id=$12',
        [firstName, lastName, phone, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd, req.params.id]
      );
    }
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    if (isHeadAdminOnly(req)) {
      const target = await pool.query('SELECT roles, title FROM users WHERE id=$1', [req.params.id]);
      const targetRoles = target.rows[0] ? (Array.isArray(target.rows[0].roles) && target.rows[0].roles.length ? target.rows[0].roles : [target.rows[0].title]) : [];
      if (!headAdminCanTarget(targetRoles)) return res.status(403).json({ error: 'Head Admin can only delete Teacher, Support Teacher, or Admin accounts.' });
    }
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* STUDENTS */
app.get('/api/students', async (req, res) => {
  try {
    const [studRes, grpRes, cmtRes] = await Promise.all([
      pool.query("SELECT * FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial') ORDER BY created_at DESC"),
      pool.query('SELECT id,name,teacher,level,time,start_date,student_ids FROM groups'),
      pool.query(`SELECT DISTINCT ON (student_id) student_id, text, actor, created_at
                  FROM student_comments ORDER BY student_id, created_at DESC`)
    ]);
    const groups = grpRes.rows;
    const studentGroups = {};
    for (const g of groups) {
      for (const sid of (g.student_ids || [])) {
        if (!studentGroups[sid]) studentGroups[sid] = [];
        studentGroups[sid].push(g);
      }
    }
    const lastComment = {};
    for (const c of cmtRes.rows) lastComment[c.student_id] = c;
    const enrolled = new Set(groups.flatMap(g => g.student_ids || []));
    res.json(studRes.rows.map(s => {
      const lc = lastComment[s.id];
      return {
        id: s.id, firstName: s.first_name, lastName: s.last_name,
        phone: s.phone, phoneParent: s.phone_parent, phoneMother: s.phone_mother, phoneOther: s.phone_other,
        level: s.level,
        status: enrolled.has(s.id) ? (s.status === 'Frozen' ? 'Frozen' : 'Active') : 'Inactive',
        balance: Number(s.balance || 0),
        balance_frozen: s.balance_frozen || false,
        frozen_comment: s.frozen_comment || null,
        exam: s.exam, examDate: s.exam_date, notes: s.notes, createdAt: s.created_at,
        school: s.school, grade: s.grade, address: s.address,
        groups: (studentGroups[s.id] || []).map(g => ({
          id: g.id, name: g.name, level: g.level, teacher: g.teacher,
          time: g.time, startDate: g.start_date
        })),
        lastComment: lc ? {
          text: lc.text, actor: lc.actor,
          time: new Date(lc.created_at).toLocaleString('en-GB', {
            timeZone: 'Asia/Tashkent', day:'2-digit', month:'2-digit', year:'numeric',
            hour:'2-digit', minute:'2-digit', hour12: false
          })
        } : null
      };
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/students', async (req, res) => {
  try {
    const { firstName, lastName, phone, phoneParent, phoneMother, phoneOther, level, status, exam, examDate, notes, school, grade, address } = req.body;
    let id;
    do {
      id = String(Math.floor(10000 + Math.random() * 90000));
      var existing = await pool.query('SELECT 1 FROM students WHERE id=$1', [id]);
    } while (existing.rows.length > 0);
    await pool.query(
      'INSERT INTO students(id,first_name,last_name,phone,phone_parent,phone_mother,phone_other,level,status,exam,exam_date,notes,school,grade,address) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',
      [id, firstName, lastName, phone||null, phoneParent||null, phoneMother||null, phoneOther||null, level||null, status||'Active', exam||null, examDate||null, notes||null, school||null, grade||null, address||null]
    );
    const actor = req.user ? req.user.first_name+' '+req.user.last_name : 'Someone';
    await notifyRole('staff', 'new_student', 'New student enrolled',
      `${firstName} ${lastName} was added by ${actor}`, 'students.html', req.user?.id);
    broadcast('students');
    res.json({ ok: true, id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, phoneParent, phoneMother, phoneOther, level, status, exam, examDate, notes, school, grade, address, balance_frozen, frozen_comment } = req.body;
    await pool.query(
      'UPDATE students SET first_name=$1,last_name=$2,phone=$3,phone_parent=$4,phone_mother=$5,phone_other=$6,level=$7,status=$8,exam=$9,exam_date=$10,notes=$11,school=$12,grade=$13,address=$14,balance_frozen=$15,frozen_comment=$16 WHERE id=$17',
      [firstName, lastName, phone||null, phoneParent||null, phoneMother||null, phoneOther||null, level||null, status||'Active', exam||null, examDate||null, notes||null, school||null, grade||null, address||null, balance_frozen||false, frozen_comment||null, req.params.id]
    );
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/students/:id', async (req, res) => {
  try {
    const { reason, comment } = req.body || {};
    const sid = req.params.id;
    // Save current status before overwriting it
    const { rows: cur } = await pool.query('SELECT status FROM students WHERE id=$1', [sid]);
    const preStatus = cur[0]?.status || null;
    await pool.query(
      `UPDATE students SET archived=TRUE, archive_reason=$1, archive_comment=$2, archived_at=NOW(), status='Inactive', pre_archive_status=$3 WHERE id=$4`,
      [reason||null, comment||null, preStatus, sid]
    );
    // Remove from all groups' student_ids
    const { rows: grps } = await pool.query(
      `SELECT id, student_ids FROM groups WHERE student_ids @> $1::jsonb`,
      [JSON.stringify([sid])]
    );
    for (const g of grps) {
      const updated = (g.student_ids || []).filter(id => id !== sid);
      await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(updated), g.id]);
    }
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/students/archived', async (req, res) => {
  try {
    const [{ rows: students }, { rows: leads }] = await Promise.all([
      pool.query(`SELECT * FROM students WHERE archived=TRUE ORDER BY archived_at DESC`),
      pool.query(`SELECT * FROM leads WHERE archived=TRUE ORDER BY archived_at DESC`)
    ]);
    const result = [
      ...students.map(s => ({
        id: s.id, firstName: s.first_name, lastName: s.last_name,
        phone: s.phone, level: s.level,
        archiveReason: s.archive_reason,
        archiveComment: s.archive_comment,
        archivedAt: s.archived_at,
        preArchiveStatus: s.pre_archive_status,
        sourceType: 'student'
      })),
      ...leads.map(l => ({
        id: l.id, firstName: l.first_name, lastName: l.last_name,
        phone: l.phone_student || l.phone_father || l.phone_mother || l.phone_other,
        level: l.current_level,
        archiveReason: l.archive_reason,
        archiveComment: l.archive_comment,
        archivedAt: l.archived_at,
        preArchiveStatus: l.pre_archive_status,
        sourceType: 'lead'
      }))
    ];
    result.sort((a,b) => new Date(b.archivedAt||0) - new Date(a.archivedAt||0));
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Archive reasons management
app.get('/api/archive-reasons', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM archive_reasons ORDER BY label');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/archive-reasons', async (req, res) => {
  try {
    const { label, isBlacklist } = req.body;
    if (!label?.trim()) return res.status(400).json({ error: 'Label required' });
    if (label.trim().toLowerCase() === 'blacklist') return res.status(400).json({ error: 'Blacklist is a fixed reason and cannot be added as custom' });
    const { rows } = await pool.query(
      'INSERT INTO archive_reasons(label, is_blacklist) VALUES($1,$2) ON CONFLICT(label) DO NOTHING RETURNING *',
      [label.trim(), isBlacklist || false]
    );
    res.json(rows[0] || { error: 'Already exists' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/archive-reasons/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM archive_reasons WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Blacklist check — used during new student registration
app.get('/api/students/blacklist-check', async (req, res) => {
  try {
    const { name, phone } = req.query;
    // 'Blacklist' is a fixed built-in reason — always included regardless of the archive_reasons table
    const blacklistLabels = ['Blacklist'];

    const conditions = [];
    const params = [blacklistLabels];
    let idx = 2;
    if (name && name.trim()) {
      // Match first+last name fuzzy: both parts present in full name
      const parts = name.trim().toLowerCase().split(/\s+/);
      parts.forEach(p => {
        conditions.push(`LOWER(first_name || ' ' || last_name) LIKE $${idx}`);
        params.push('%' + p + '%');
        idx++;
      });
    }
    if (phone && phone.trim().length >= 7) {
      conditions.push(`phone LIKE $${idx}`);
      params.push('%' + phone.trim().replace(/\s/g,'').slice(-7) + '%');
      idx++;
    }
    if (!conditions.length) return res.json([]);

    const where = `archived=TRUE AND archive_reason = ANY($1) AND (${conditions.join(' OR ')})`;

    const [{ rows: students }, { rows: leads }] = await Promise.all([
      pool.query(
        `SELECT id, first_name, last_name, phone, archive_reason, archive_comment, archived_at FROM students WHERE ${where}`,
        params
      ),
      pool.query(
        `SELECT id, first_name, last_name, phone_student AS phone, archive_reason, archive_comment, archived_at FROM leads WHERE ${where}`,
        params
      )
    ]);
    const all = [...students, ...leads];
    res.json(all.map(s => ({
      id: s.id,
      name: s.first_name + ' ' + s.last_name,
      phone: s.phone,
      reason: s.archive_reason,
      comment: s.archive_comment,
      archivedAt: s.archived_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/students/:id/permanent', async (req, res) => {
  try {
    const sid = req.params.id;
    await pool.query('DELETE FROM student_comments WHERE student_id=$1', [sid]);
    await pool.query('DELETE FROM student_calls WHERE student_id=$1', [sid]);
    await pool.query('DELETE FROM invoices WHERE student_id=$1', [sid]);
    await pool.query('DELETE FROM attendance WHERE student_id=$1', [sid]);
    await pool.query('DELETE FROM students WHERE id=$1', [sid]);
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id/restore', async (req, res) => {
  try {
    await pool.query(
      `UPDATE students SET archived=FALSE, archive_reason=NULL, archive_comment=NULL, archived_at=NULL, pre_archive_status=NULL, status='Inactive' WHERE id=$1`,
      [req.params.id]
    );
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups/:id/archived-students', async (req, res) => {
  try {
    const grp = await pool.query('SELECT student_ids FROM groups WHERE id=$1', [req.params.id]);
    const ids = grp.rows[0]?.student_ids || [];
    if (!ids.length) return res.json([]);
    const { rows } = await pool.query(
      `SELECT * FROM students WHERE id=ANY($1) AND archived=TRUE ORDER BY archived_at DESC`,
      [ids]
    );
    res.json(rows.map(s => ({
      id: s.id, firstName: s.first_name, lastName: s.last_name,
      phone: s.phone, level: s.level,
      archiveReason: s.archive_reason,
      archivedAt: s.archived_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});


/* STUDENT DETAIL endpoints */
app.get('/api/students/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM students WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    const s = rows[0];
    // Same rule as the list endpoint: a student not enrolled in any group shows as Inactive
    const enr = await pool.query('SELECT 1 FROM groups WHERE student_ids @> $1::jsonb LIMIT 1', [JSON.stringify([s.id])]);
    res.json({ id: s.id, firstName: s.first_name, lastName: s.last_name,
      phone: s.phone, phoneParent: s.phone_parent, phoneMother: s.phone_mother, phoneOther: s.phone_other,
      level: s.level, status: enr.rows.length ? (s.status === 'Frozen' ? 'Frozen' : 'Active') : 'Inactive', balance: Number(s.balance||0),
      exam: s.exam, examDate: s.exam_date, notes: s.notes, createdAt: s.created_at,
      school: s.school, grade: s.grade, address: s.address });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Activate student: set status Active + auto-calculate pro-rated payment
app.post('/api/students/:id/activate', async (req, res) => {
  try {
    const { groupId } = req.body;
    const studentId = req.params.id;

    // Fetch group
    const grpRes = await pool.query('SELECT * FROM groups WHERE id=$1', [groupId]);
    const g = grpRes.rows[0];
    if (!g) return res.status(404).json({ error: 'Group not found' });

    // Activate student
    await pool.query("UPDATE students SET status='Active' WHERE id=$1", [studentId]);

    let monthlyPrice = Math.abs(Number(g.price || 0));
    if (monthlyPrice === 0 && g.level) {
      const prRes = await pool.query('SELECT price FROM pricing WHERE level=$1', [g.level]);
      monthlyPrice = Math.abs(Number(prRes.rows[0]?.price || 0));
    }

    if (monthlyPrice > 0) {
      // Calculate pro-rated amount based on remaining lessons this month
      function getLessonDays(schedType, customDays) {
        if (schedType === 'odd')    return [1, 3, 5];
        if (schedType === 'even')   return [2, 4, 6];
        if (schedType === 'daily')  return [1, 2, 3, 4, 5];
        if (schedType === 'custom' && customDays?.length) {
          const map = { Mon:1, Tue:2, Wed:3, Thu:4, Fri:5, Sat:6, Sun:0 };
          return customDays.map(d => map[d]).filter(d => d !== undefined);
        }
        return [1, 3, 5];
      }
      function countLessons(year, month, days, fromDay) {
        const last = new Date(year, month + 1, 0).getDate();
        let n = 0;
        for (let d = fromDay; d <= last; d++) {
          if (days.includes(new Date(year, month, d).getDay())) n++;
        }
        return n;
      }

      const now        = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
      const year       = now.getFullYear(), month = now.getMonth(), today = now.getDate();
      let customDays = g.custom_days;
      if (typeof customDays === 'string') { try { customDays = JSON.parse(customDays); } catch(e) { customDays = []; } }
      const lessonDays = getLessonDays(g.sched_type, customDays);
      const remaining = Math.max(0, countLessons(year, month, lessonDays, today));
      const amount    = Math.round((monthlyPrice / 12) * remaining / 1000) * 1000;

      // Record invoice + update balance
      const invId  = 'inv-' + Date.now();
      const invNum = 'INV-' + Date.now().toString().slice(-6);
      const mStr   = `${year}-${String(month + 1).padStart(2, '0')}`;
      await pool.query(
        `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type)
         VALUES($1,$2,$3,$4,$5,$6,$7,'Pending','Auto')`,
        [invId, invNum, studentId, groupId, mStr,
         `Activation – ${remaining} of 12 lessons (${g.name})`, amount]
      );

      const stuRes = await pool.query('SELECT balance FROM students WHERE id=$1', [studentId]);
      const newBal = Number(stuRes.rows[0]?.balance || 0) - amount;
      await pool.query('UPDATE students SET balance=$1 WHERE id=$2', [newBal, studentId]);

      broadcast('students');
      return res.json({ ok: true, amount, remaining });
    }

    broadcast('students');
    res.json({ ok: true, amount: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Adjust balance (add payment)
app.post('/api/students/:id/payment', async (req, res) => {
  try {
    const { amount, paymentType, groupId, desc, notes, creator } = req.body;
    const num = Number(amount);
    // Update balance
    await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [num, req.params.id]);
    // Create invoice
    const id = 'inv-' + Date.now();
    const number = 'INV-' + Date.now().toString().slice(-6);
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const month = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0');
    await pool.query(
      `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type,notes,creator)
       VALUES($1,$2,$3,$4,$5,$6,$7,'Paid',$8,$9,$10)`,
      [id, number, req.params.id, groupId||null, month, desc||'Payment', num, paymentType||'Cash', notes||null, creator||null]
    );
    const balRes = await pool.query('SELECT balance FROM students WHERE id=$1', [req.params.id]);
    const newBalance = Number(balRes.rows[0]?.balance || 0);
    broadcast('students');
    broadcast('finance');
    res.json({ ok: true, newBalance });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Comments
app.get('/api/students/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM student_comments WHERE student_id=$1 ORDER BY created_at DESC', [req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/students/:id/comments', async (req, res) => {
  try {
    const { text, actor } = req.body;
    await pool.query('INSERT INTO student_comments(student_id,text,actor) VALUES($1,$2,$3)', [req.params.id, text, actor||null]);
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/students/comments/:commentId', async (req, res) => {
  try {
    await pool.query('DELETE FROM student_comments WHERE id=$1', [req.params.commentId]);
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Call history
app.get('/api/students/:id/calls', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM student_calls WHERE student_id=$1 ORDER BY created_at DESC', [req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/students/:id/calls', async (req, res) => {
  try {
    const { note, actor } = req.body;
    await pool.query('INSERT INTO student_calls(student_id,note,actor) VALUES($1,$2,$3)', [req.params.id, note, actor||null]);
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/students/calls/:callId', async (req, res) => {
  try {
    await pool.query('DELETE FROM student_calls WHERE id=$1', [req.params.callId]);
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Groups this student belongs to
app.get('/api/students/:id/groups', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM groups WHERE student_ids @> $1::jsonb ORDER BY created_at DESC`,
      [JSON.stringify([req.params.id])]
    );
    res.json(rows.map(g => ({
      id: g.id, name: g.name, teacher: g.teacher, room: g.room,
      level: g.level, schedType: g.sched_type, time: g.time,
      duration: g.duration, startDate: g.start_date,
      currentUnit: g.current_unit, price: Number(g.price||0)
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Invoices for a student
app.get('/api/students/:id/invoices', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM invoices WHERE student_id=$1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json(rows.map(i => ({
      id: i.id, number: i.number, groupId: i.group_id,
      level: i.level, month: i.month, desc: i.description,
      total: Number(i.total), dueDate: i.due_date,
      status: i.status, paymentType: i.payment_type,
      notes: i.notes, creator: i.creator, createdAt: i.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* TEACHERS */
// Teachers are now Staff users with the 'Teacher' role.
app.get('/api/teachers', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT id,first_name,last_name,phone,created_at FROM users WHERE title='Teacher' ORDER BY first_name");
    res.json(rows.map(t => ({
      id: t.id, firstName: t.first_name, lastName: t.last_name,
      phone: t.phone, status: 'Active', createdAt: t.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/teachers', async (req, res) => {
  try {
    const { id, firstName, lastName, phone, password } = req.body;
    const pwErr = validateCreatePassword(password);
    if (pwErr) return res.status(400).json({ error: pwErr });
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    await pool.query(
      "INSERT INTO users(id,first_name,last_name,phone,password,role,title,avatar,permissions,must_change_password) VALUES($1,$2,$3,$4,$5,'Teacher','Teacher',$6,$7,TRUE)",
      [id, firstName, lastName, phone, password, avatar, JSON.stringify(permsForRole('Teacher'))]
    );
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/teachers/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, password } = req.body;
    const newName = `${firstName} ${lastName}`;
    const old = await pool.query('SELECT first_name, last_name FROM users WHERE id=$1', [req.params.id]);
    const oldName = old.rows[0] ? `${old.rows[0].first_name} ${old.rows[0].last_name}` : null;
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    if (password) {
      const pwErr = validateCreatePassword(password);
      if (pwErr) return res.status(400).json({ error: pwErr });
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,password=$4,avatar=$5,must_change_password=TRUE WHERE id=$6',
        [firstName, lastName, phone, password, avatar, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,avatar=$4 WHERE id=$5',
        [firstName, lastName, phone, avatar, req.params.id]
      );
    }
    if (oldName && oldName !== newName) {
      await pool.query('UPDATE groups SET teacher=$1 WHERE teacher=$2', [newName, oldName]);
    }
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/teachers/:id', async (req, res) => {
  try {
    const old = await pool.query('SELECT first_name, last_name FROM users WHERE id=$1', [req.params.id]);
    if (old.rows[0]) {
      const name = `${old.rows[0].first_name} ${old.rows[0].last_name}`;
      await pool.query('UPDATE groups SET teacher=NULL WHERE teacher=$1', [name]);
    }
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    broadcast('users');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* GROUPS */
app.get('/api/groups', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM groups ORDER BY created_at DESC');
    // Get all trial lead IDs so we can exclude them from student counts
    const trialRes = await pool.query(`SELECT id FROM leads WHERE status='Trial'`);
    const trialIdSet = new Set(trialRes.rows.map(r => r.id));
    res.json(rows.map(g => ({
      id: g.id, name: g.name, teacher: g.teacher, room: g.room,
      level: g.level, lang: g.lang, maxStudents: g.max_students,
      schedType: g.sched_type, customDays: g.custom_days,
      time: g.time, duration: g.duration, startDate: g.start_date,
      notes: g.notes,
      // Exclude trial lead IDs — they are not enrolled students
      studentIds: (g.student_ids || []).filter(id => !trialIdSet.has(id)),
      currentUnit: g.current_unit || '1A',
      price: Number(g.price || 0),
      createdAt: g.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups', async (req, res) => {
  try {
    const { id, name, teacher, room, level, lang, maxStudents, schedType, customDays, time, duration, startDate, notes, studentIds, currentUnit, price } = req.body;
    await pool.query(
      'INSERT INTO groups(id,name,teacher,room,level,lang,max_students,sched_type,custom_days,time,duration,start_date,notes,student_ids,current_unit,price) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)',
      [id, name, teacher||null, room||null, level||null, lang||'UZ', maxStudents||null, schedType||'odd', JSON.stringify(customDays||[]), time||null, duration||90, startDate||null, notes||null, JSON.stringify(studentIds||[]), currentUnit||'1A', price||0]
    );
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/groups/:id', async (req, res) => {
  try {
    const { name, teacher, room, level, lang, maxStudents, schedType, customDays, time, duration, startDate, notes, studentIds, currentUnit, price } = req.body;
    await pool.query(
      'UPDATE groups SET name=$1,teacher=$2,room=$3,level=$4,lang=$5,max_students=$6,sched_type=$7,custom_days=$8,time=$9,duration=$10,start_date=$11,notes=$12,student_ids=$13,current_unit=$14,price=$15 WHERE id=$16',
      [name, teacher||null, room||null, level||null, lang||'UZ', maxStudents||null, schedType||'odd', JSON.stringify(customDays||[]), time||null, duration||90, startDate||null, notes||null, JSON.stringify(studentIds||[]), currentUnit||'1A', price||0, req.params.id]
    );
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM groups WHERE id=$1', [req.params.id]);
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM group_comments WHERE group_id=$1 ORDER BY created_at DESC', [req.params.id]);
    res.json(rows.map(c => ({
      id: c.id, text: c.text, actor: c.actor,
      time: new Date(c.created_at).toLocaleString('en-GB', { timeZone:'Asia/Tashkent', day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit', hour12:false })
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/:id/comments', async (req, res) => {
  try {
    const { text, actor } = req.body;
    await pool.query('INSERT INTO group_comments(group_id,text,actor) VALUES($1,$2,$3)', [req.params.id, text, actor||null]);
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/comments/:commentId', async (req, res) => {
  try {
    await pool.query('DELETE FROM group_comments WHERE id=$1', [req.params.commentId]);
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/:id/students', async (req, res) => {
  try {
    const { studentIds } = req.body;
    const prev = await pool.query('SELECT student_ids, name, teacher FROM groups WHERE id=$1', [req.params.id]);
    const prevIds = prev.rows[0]?.student_ids || [];
    const groupName = prev.rows[0]?.name || 'a group';
    const teacherName = prev.rows[0]?.teacher || null;
    const newSet = new Set(studentIds || []);
    const removed = prevIds.filter(id => !newSet.has(id));
    const added = (studentIds || []).filter(id => !prevIds.includes(id));
    await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(studentIds||[]), req.params.id]);
    // Notify the group's teacher when new students are added to their group
    if (added.length && teacherName) {
      const teacherUser = await pool.query(
        `SELECT id FROM users WHERE (first_name||' '||last_name)=$1 LIMIT 1`, [teacherName]
      ).catch(()=>({rows:[]}));
      if (teacherUser.rows.length) {
        const stuRows = await pool.query(
          `SELECT first_name||' '||last_name AS name FROM students WHERE id=ANY($1)`,
          [added]
        ).catch(()=>({rows:[]}));
        const names = stuRows.rows.map(r=>r.name).join(', ');
        await createNotif(teacherUser.rows[0].id, 'new_student',
          `New student${added.length>1?'s':''} added to your group`,
          `${names} added to ${groupName}`, 'students.html');
      }
    }
    // Deactivate removed students and freeze their finances
    if (removed.length) {
      const allGroups = await pool.query('SELECT student_ids FROM groups WHERE id!=$1', [req.params.id]);
      const stillEnrolled = new Set(allGroups.rows.flatMap(g => g.student_ids || []));
      for (const sid of removed) {
        if (!stillEnrolled.has(sid)) {
          await pool.query("UPDATE students SET status='Inactive' WHERE id=$1", [sid]);
          // Cancel pending Auto invoices and reverse their balance impact
          const { rows: pending } = await pool.query(
            `SELECT id, total FROM invoices WHERE student_id=$1 AND status='Pending' AND payment_type='Auto'`,
            [sid]
          );
          if (pending.length) {
            const totalToReverse = pending.reduce((s, i) => s + Number(i.total || 0), 0);
            await pool.query(
              `UPDATE invoices SET status='Cancelled' WHERE student_id=$1 AND status='Pending' AND payment_type='Auto'`,
              [sid]
            );
            await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [totalToReverse, sid]);
          }
        }
      }
    }
    broadcast('groups');
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/:id/unit', async (req, res) => {
  try {
    const { unit } = req.body;
    await pool.query('UPDATE groups SET current_unit=$1 WHERE id=$2', [unit, req.params.id]);
    broadcast('groups');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* CUSTOM LEVELS */
app.get('/api/levels', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT level FROM custom_levels ORDER BY created_at');
    res.json(rows.map(r => r.level));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/levels', async (req, res) => {
  try {
    const { level } = req.body;
    await pool.query('INSERT INTO custom_levels(level) VALUES($1) ON CONFLICT DO NOTHING', [level]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/levels/:level', async (req, res) => {
  try {
    await pool.query('DELETE FROM custom_levels WHERE level=$1', [req.params.level]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* PRICING */
app.get('/api/pricing', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM pricing ORDER BY level');
    res.json(rows.map(r => ({ level: r.level, price: Number(r.price) })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pricing/:level', async (req, res) => {
  try {
    const { price } = req.body;
    await pool.query(
      'INSERT INTO pricing(level,price) VALUES($1,$2) ON CONFLICT(level) DO UPDATE SET price=$2, updated_at=NOW()',
      [req.params.level, price]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* INVOICES */
app.get('/api/invoices', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM invoices ORDER BY created_at DESC');
    res.json(rows.map(i => ({
      id: i.id, number: i.number,
      studentId: i.student_id, groupId: i.group_id,
      level: i.level, month: i.month,
      desc: i.description, total: Number(i.total),
      dueDate: i.due_date, status: i.status,
      paymentType: i.payment_type,
      notes: i.notes, creator: i.creator, createdAt: i.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/invoices', async (req, res) => {
  try {
    const { id, number, studentId, groupId, level, month, desc, total, dueDate, status, paymentType, notes, creator } = req.body;
    await pool.query(
      `INSERT INTO invoices(id,number,student_id,group_id,level,month,description,total,due_date,status,payment_type,notes,creator)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [id, number, studentId, groupId||null, level||null, month||null, desc||null,
       total||0, dueDate||null, status||'Pending', paymentType||'Cash', notes||null, creator||null]
    );
    // A paid payment credits the student's balance (mirrors DELETE which debits it back)
    if (studentId && (status||'Pending') === 'Paid' && paymentType !== 'Auto') {
      await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [Number(total)||0, studentId]);
    }
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/invoices/:id', async (req, res) => {
  try {
    const { studentId, groupId, level, month, desc, total, dueDate, status, paymentType, notes } = req.body;
    const prevRes = await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id]);
    const prev = prevRes.rows[0];
    await pool.query(
      `UPDATE invoices SET student_id=$1,group_id=$2,level=$3,month=$4,description=$5,
       total=$6,due_date=$7,status=$8,payment_type=$9,notes=$10 WHERE id=$11`,
      [studentId, groupId||null, level||null, month||null, desc||null,
       total||0, dueDate||null, status||'Pending', paymentType||'Cash', notes||null, req.params.id]
    );
    // Keep student balances in sync: undo the old paid amount, apply the new one
    if (prev) {
      const wasPaid = prev.status === 'Paid' && prev.payment_type !== 'Auto';
      const isPaid  = (status||'Pending') === 'Paid' && paymentType !== 'Auto';
      if (wasPaid && prev.student_id) {
        await pool.query('UPDATE students SET balance=balance-$1 WHERE id=$2', [Number(prev.total)||0, prev.student_id]);
      }
      if (isPaid && studentId) {
        await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [Number(total)||0, studentId]);
      }
    }
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/invoices/:id/status', async (req, res) => {
  try {
    const { status, paymentType } = req.body;
    await pool.query('UPDATE invoices SET status=$1,payment_type=$2 WHERE id=$3', [status, paymentType||'Cash', req.params.id]);
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/invoices/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id]);
    const inv = rows[0];
    if (inv) {
      const isCharge = inv.payment_type === 'Auto' || (inv.description||'').toLowerCase().startsWith('activation');
      const delta = isCharge ? Number(inv.total) : -Number(inv.total);
      if (inv.student_id) {
        await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [delta, inv.student_id]);
      }
    }
    await pool.query('DELETE FROM invoices WHERE id=$1', [req.params.id]);
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* SPENDINGS */
app.get('/api/spendings', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM spendings ORDER BY created_at DESC');
    res.json(rows.map(r => ({ id:r.id, amount:Number(r.amount), category:r.category, description:r.description, month:r.month, createdAt:r.created_at })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/spendings', async (req, res) => {
  try {
    const { id, amount, category, description, month } = req.body;
    await pool.query(
      'INSERT INTO spendings(id,amount,category,description,month) VALUES($1,$2,$3,$4,$5)',
      [id, Number(amount)||0, category||null, description||null, month||null]
    );
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/spendings/:id', async (req, res) => {
  try {
    const { amount, category, description, month } = req.body;
    await pool.query(
      'UPDATE spendings SET amount=$1,category=$2,description=$3,month=$4 WHERE id=$5',
      [Number(amount)||0, category||null, description||null, month||null, req.params.id]
    );
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/spendings/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM spendings WHERE id=$1', [req.params.id]);
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* SUPPORT SESSIONS — one-time lessons, one room, max 2 teachers at a time */
function toMin(t){ const [h,m]=String(t||'0:0').split(':').map(Number); return (h||0)*60+(m||0); }
function dateDayType(dateStr){ const dow=new Date(dateStr+'T00:00:00').getDay(); if([1,3,5].includes(dow))return 'odd'; if([2,4,6].includes(dow))return 'even'; return null; }

app.get('/api/support-teachers', async (req, res) => {
  try {
    const me = req.user;
    const myName = me.first_name + ' ' + me.last_name;
    const userRoles = Array.isArray(me.roles) && me.roles.length ? me.roles : [me.title];
    const isSupport = userRoles.some(r => String(r).trim().toLowerCase() === 'support teacher');
    const adminRoles = ['CEO','Head Admin','Manager','Admin'];
    const isAdmin = userRoles.some(r => adminRoles.includes(r));
    const { rows } = await pool.query("SELECT id, first_name, last_name, support_odd_start, support_odd_end, support_even_start, support_even_end FROM users WHERE title='Support Teacher' OR roles @> '[\"Support Teacher\"]' ORDER BY first_name");
    let result = rows.map(u => ({
      id: u.id, name: u.first_name+' '+u.last_name,
      odd:  u.support_odd_start  ? { start:u.support_odd_start,  end:u.support_odd_end  } : null,
      even: u.support_even_start ? { start:u.support_even_start, end:u.support_even_end } : null,
    }));
    // Non-admin support teachers only see themselves
    if (isSupport && !isAdmin) result = result.filter(t => t.name === myName);
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/support/:date', async (req, res) => {
  try {
    const me = req.user;
    const myName = me.first_name + ' ' + me.last_name;
    const userRoles = Array.isArray(me.roles) && me.roles.length ? me.roles : [me.title];
    const isSupport = userRoles.some(r => String(r).trim().toLowerCase() === 'support teacher');
    const adminRoles = ['CEO','Head Admin','Manager','Admin'];
    const isAdmin = userRoles.some(r => adminRoles.includes(r));
    const { rows } = isSupport && !isAdmin
      ? await pool.query('SELECT * FROM support_sessions WHERE date=$1 AND teacher=$2 ORDER BY time', [req.params.date, myName])
      : await pool.query('SELECT * FROM support_sessions WHERE date=$1 ORDER BY time', [req.params.date]);
    res.json(rows.map(s => ({ id:s.id, date:s.date, time:s.time, duration:s.duration, teacher:s.teacher, studentId:s.student_id })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/support', async (req, res) => {
  try {
    const { id, date, time, duration, teacher, studentId, theme } = req.body;
    if (!date || !time || !teacher || !studentId) return res.status(400).json({ error: 'Date, time, teacher and student are required.' });
    if (!theme || !theme.trim()) return res.status(400).json({ error: 'Theme is required.' });
    // Block past times
    const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const todayISO = nowTz.toISOString().split('T')[0];
    if (date < todayISO) return res.status(409).json({ error: 'Cannot book sessions in the past.' });
    if (date === todayISO) {
      const [hh, mm] = time.split(':').map(Number);
      const slotMin = hh * 60 + mm;
      const nowMin = nowTz.getHours() * 60 + nowTz.getMinutes();
      if (slotMin <= nowMin) return res.status(409).json({ error: 'This time slot has already passed.' });
    }
    const dur = Number(duration) === 60 ? 60 : 30;
    const start = toMin(time), end = start + dur;
    // Enforce the teacher's working shift for this day type (odd/even).
    const tRes = await pool.query("SELECT support_odd_start, support_odd_end, support_even_start, support_even_end FROM users WHERE (title='Support Teacher' OR roles @> '[\"Support Teacher\"]') AND (first_name||' '||last_name)=$1 LIMIT 1", [teacher]);
    const sh = tRes.rows[0];
    if (sh) {
      const dt = dateDayType(date);
      const shiftStart = dt==='odd' ? sh.support_odd_start : dt==='even' ? sh.support_even_start : null;
      const shiftEnd   = dt==='odd' ? sh.support_odd_end   : dt==='even' ? sh.support_even_end   : null;
      if (!shiftStart) return res.status(409).json({ error: 'This teacher does not work on this day.' });
      if (start < toMin(shiftStart) || end > toMin(shiftEnd)) return res.status(409).json({ error: "Outside this teacher's working hours." });
    }
    // Block fined students
    const fineCheck = await pool.query('SELECT 1 FROM support_fines WHERE student_id=$1 AND blocked_until > NOW() LIMIT 1', [studentId]);
    if (fineCheck.rows.length) return res.status(409).json({ error: 'This student is currently fined and cannot book support sessions.' });

    const { rows } = await pool.query('SELECT * FROM support_sessions WHERE date=$1', [date]);
    const overlap = rows.filter(s => { const st=toMin(s.time), en=st+Number(s.duration||30); return start < en && st < end; });
    if (overlap.length >= 2) return res.status(409).json({ error: 'Both support slots are already taken at this time.' });
    if (overlap.some(s => s.teacher === teacher)) return res.status(409).json({ error: 'This teacher already has a session at this time.' });
    await pool.query(
      'INSERT INTO support_sessions(id,date,time,duration,teacher,student_id,theme) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [id, date, time, dur, teacher, studentId, theme.trim()]
    );
    broadcast('support');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/support/:id', async (req, res) => {
  const adminRoles = ['CEO','Head Admin','Manager','Admin'];
  const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
  if (!userRoles.some(r => adminRoles.includes(r)))
    return res.status(403).json({ error: 'Only administration can delete support sessions.' });
  try { await pool.query('DELETE FROM support_sessions WHERE id=$1', [req.params.id]); broadcast('support'); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Mark attendance + optional theme for a session
app.put('/api/support/:id/attend', async (req, res) => {
  try {
    const { attended, theme } = req.body;
    await pool.query('UPDATE support_sessions SET attended=$1, theme=$2 WHERE id=$3', [attended, theme||null, req.params.id]);
    // Fine check: if marked absent, see if student has 2+ absences this calendar month
    if (attended === false) {
      const sess = await pool.query('SELECT student_id, date FROM support_sessions WHERE id=$1', [req.params.id]);
      if (sess.rows[0]) {
        const { student_id } = sess.rows[0];
        const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0,0,0,0);
        const absences = await pool.query(
          `SELECT COUNT(*)::int n FROM support_sessions WHERE student_id=$1 AND attended=false AND date >= $2`,
          [student_id, monthStart.toISOString().split('T')[0]]
        );
        if (absences.rows[0].n >= 2) {
          const activeFine = await pool.query(
            `SELECT 1 FROM support_fines WHERE student_id=$1 AND blocked_until > NOW() LIMIT 1`,
            [student_id]
          );
          if (!activeFine.rows.length) {
            const { genId } = require('crypto'); // fallback
            const fineId = require('crypto').randomUUID();
            const blockedUntil = new Date(Date.now() + 30*24*60*60*1000);
            await pool.query('INSERT INTO support_fines(id,student_id,blocked_until) VALUES($1,$2,$3)',
              [fineId, student_id, blockedUntil.toISOString()]);
          }
        }
      }
    }
    broadcast('support');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Support dashboard: my students + today's sessions + fines
app.get('/api/support-dashboard', async (req, res) => {
  try {
    const me = req.user;
    const myName = me.first_name + ' ' + me.last_name;
    const today = new Date(new Date().toLocaleString('en-US', { timeZone:'Asia/Tashkent' })).toISOString().split('T')[0];

    const userRoles = Array.isArray(me.roles) && me.roles.length ? me.roles : [me.title];
    const isSupport = userRoles.some(r => String(r).trim().toLowerCase() === 'support teacher');

    const tzNow = new Date(new Date().toLocaleString('en-US', { timeZone:'Asia/Tashkent' }));
    const monthStart = `${tzNow.getFullYear()}-${String(tzNow.getMonth()+1).padStart(2,'0')}-01`;

    const [stuR, fineR, todayR, monthR, shiftR, historyR] = await Promise.all([
      pool.query('SELECT id, first_name, last_name FROM students WHERE archived IS NOT TRUE'),
      pool.query('SELECT student_id, blocked_until FROM support_fines WHERE blocked_until > NOW()'),
      isSupport
        ? pool.query(`SELECT * FROM support_sessions WHERE teacher=$1 AND date=$2 ORDER BY time`, [myName, today])
        : pool.query(`SELECT * FROM support_sessions WHERE date=$1 ORDER BY teacher, time`, [today]),
      isSupport
        ? pool.query(`SELECT teacher, duration, attended FROM support_sessions WHERE teacher=$1 AND date>=$2`, [myName, monthStart])
        : pool.query(`SELECT teacher, duration, attended FROM support_sessions WHERE date>=$1`, [monthStart]),
      isSupport
        ? pool.query(`SELECT support_odd_start, support_odd_end, support_even_start, support_even_end FROM users WHERE (first_name||' '||last_name)=$1 LIMIT 1`, [myName])
        : pool.query(`SELECT first_name||' '||last_name AS name, support_odd_start, support_odd_end, support_even_start, support_even_end FROM users WHERE title='Support Teacher' OR roles @> '["Support Teacher"]'`),
      !isSupport
        ? pool.query(`SELECT * FROM support_sessions ORDER BY date DESC, time DESC LIMIT 200`)
        : Promise.resolve({ rows: [] }),
    ]);

    const stuMap = new Map(stuR.rows.map(s => [s.id, s]));
    const fineMap = new Map(fineR.rows.map(f => [f.student_id, f.blocked_until]));

    const todaySessions = todayR.rows.map(s => {
      const stu = stuMap.get(s.student_id);
      return {
        id: s.id, time: s.time, duration: s.duration,
        studentId: s.student_id,
        studentName: stu ? stu.first_name + ' ' + stu.last_name : '?',
        teacher: s.teacher,
        attended: s.attended,
        theme: s.theme,
      };
    });

    const history = historyR.rows.map(s => {
      const stu = stuMap.get(s.student_id);
      return {
        id: s.id, date: s.date, time: s.time, duration: s.duration,
        teacher: s.teacher,
        studentName: stu ? stu.first_name + ' ' + stu.last_name : '?',
        attended: s.attended,
        theme: s.theme,
      };
    });

    // Helper: minutes → session units (30 min = 1, 60 min = 2)
    const toUnits = dur => Math.round((parseInt(dur)||30) / 30);

    // Helper: working minutes per day from shift row
    const shiftMins = (sh, isOdd) => {
      const s = isOdd ? sh.support_odd_start : sh.support_even_start;
      const e = isOdd ? sh.support_odd_end   : sh.support_even_end;
      if (!s || !e) return 0;
      const [sh1,sm1] = s.split(':').map(Number); const [eh,em] = e.split(':').map(Number);
      return Math.max(0, (eh*60+em) - (sh1*60+sm1));
    };

    // Count working days in current month up to today, compute capacity
    const countWorkingDays = (sh) => {
      let odd=0, even=0;
      const y=tzNow.getFullYear(), m=tzNow.getMonth();
      const days = tzNow.getDate();
      for (let d=1; d<=days; d++) {
        const dt = new Date(y, m, d);
        const dayNum = Math.ceil(d/1);
        if (d%2===1) odd++; else even++;
      }
      return { odd, even };
    };

    let stats = {};
    if (isSupport) {
      const sh = shiftR.rows[0] || {};
      const { odd, even } = countWorkingDays(sh);
      const capacityMins = odd * shiftMins(sh, true) + even * shiftMins(sh, false);
      const capacitySessions = Math.floor(capacityMins / 30);

      const monthSessions = monthR.rows;
      const taught = monthSessions.reduce((sum, s) => sum + toUnits(s.duration), 0);
      const absences = monthSessions.filter(s => s.attended === false).length;

      stats = {
        todayCount: todayR.rows.length,
        absencesMonth: absences,
        capacityMonth: capacitySessions,
        taughtMonth: taught,
      };
    } else {
      // Admin/CEO/Manager view
      const monthSessions = monthR.rows;
      const totalLessons = monthSessions.length;
      const heldLessons = monthSessions.filter(s => s.attended === true).length;
      const finedStudents = fineR.rows.map(f => {
        const stu = stuMap.get(f.student_id);
        return {
          name: stu ? stu.first_name+' '+stu.last_name : '?',
          studentId: f.student_id,
          blockedUntil: f.blocked_until,
        };
      });

      // Per-teacher breakdown
      const teacherMap = new Map();
      monthSessions.forEach(s => {
        if (!teacherMap.has(s.teacher)) teacherMap.set(s.teacher, { total:0, held:0 });
        const t = teacherMap.get(s.teacher);
        t.total += toUnits(s.duration);
        if (s.attended === true) t.held += toUnits(s.duration);
      });
      const teacherStats = Array.from(teacherMap.entries()).map(([name, v]) => ({ name, ...v }))
        .sort((a,b) => b.total - a.total);

      stats = {
        todayCount: todayR.rows.length,
        totalLessonsMonth: monthSessions.reduce((s,x) => s + toUnits(x.duration), 0),
        heldLessonsMonth: monthSessions.filter(x=>x.attended===true).reduce((s,x) => s + toUnits(x.duration), 0),
        finedStudents,
        teacherStats,
      };
    }

    res.json({ todaySessions, history, isAdmin: !isSupport, stats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ATTENDANCE */
// Batch: all attendance for a date across every group (one round-trip for the dashboard).
app.get('/api/attendance/day/:date', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT group_id, student_id, status FROM attendance WHERE date=$1',
      [req.params.date]
    );
    res.json(rows.map(r => ({ groupId: r.group_id, studentId: r.student_id, status: r.status })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/students/:id/attendance', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.date, a.status, a.group_id, g.name AS group_name
       FROM attendance a
       LEFT JOIN groups g ON g.id = a.group_id
       WHERE a.student_id = $1
       ORDER BY a.date DESC
       LIMIT 120`,
      [req.params.id]
    );
    res.json(rows.map(r => ({ date: r.date, status: r.status, groupId: r.group_id, groupName: r.group_name })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/attendance/:groupId/:date', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT student_id, status FROM attendance WHERE group_id=$1 AND date=$2',
      [req.params.groupId, req.params.date]
    );
    res.json(rows.map(r => ({ studentId: r.student_id, status: r.status })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/attendance/:groupId/:date', async (req, res) => {
  try {
    const { records } = req.body;
    await pool.query('DELETE FROM attendance WHERE group_id=$1 AND date=$2', [req.params.groupId, req.params.date]);
    for (const r of records) {
      await pool.query(
        'INSERT INTO attendance(group_id,date,student_id,status) VALUES($1,$2,$3,$4)',
        [req.params.groupId, req.params.date, r.studentId, r.status]
      );
    }
    broadcast('attendance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* LEADS */
app.get('/api/leads', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM leads WHERE archived IS NOT TRUE ORDER BY created_at DESC');
    res.json(rows.map(l => ({
      id: l.id, firstName: l.first_name, lastName: l.last_name,
      phoneStudent: l.phone_student, phoneFather: l.phone_father,
      phoneMother: l.phone_mother, phoneOther: l.phone_other,
      currentLevel: l.current_level, testResult: l.test_result,
      status: l.status, groupId: l.group_id, isTrial: l.is_trial, subContainer: l.sub_container||null,
      notes: l.notes, createdAt: l.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/leads', async (req, res) => {
  try {
    const { id, firstName, lastName, phoneStudent, phoneFather, phoneMother, phoneOther, currentLevel, testResult, notes } = req.body;
    await pool.query(
      `INSERT INTO leads(id,first_name,last_name,phone_student,phone_father,phone_mother,phone_other,current_level,test_result,notes,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Registration')`,
      [id, firstName, lastName, phoneStudent||null, phoneFather||null, phoneMother||null, phoneOther||null, currentLevel||null, testResult||null, notes||null]
    );
    const actor = req.user ? req.user.first_name+' '+req.user.last_name : 'Someone';
    await notifyRole('staff', 'new_lead', 'New lead registered',
      `${firstName} ${lastName} registered by ${actor}`, 'leads.html', req.user?.id);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/leads/:id', async (req, res) => {
  try {
    const { firstName, lastName, phoneStudent, phoneFather, phoneMother, phoneOther, currentLevel, testResult, status, groupId, isTrial, notes } = req.body;
    await pool.query(
      `UPDATE leads SET first_name=$1,last_name=$2,phone_student=$3,phone_father=$4,phone_mother=$5,phone_other=$6,
       current_level=$7,test_result=$8,status=$9,group_id=$10,is_trial=$11,notes=$12,sub_container=$13 WHERE id=$14`,
      [firstName, lastName, phoneStudent||null, phoneFather||null, phoneMother||null, phoneOther||null,
       currentLevel||null, testResult||null, status||'Registration', groupId||null, isTrial||false, notes||null, req.body.subContainer||null, req.params.id]
    );
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX: to-trial now generates a new student ID so group student_ids stays consistent
app.post('/api/leads/:id/to-trial', async (req, res) => {
  try {
    const { groupId } = req.body;
    const leadId = req.params.id;
    // Update lead status only — do NOT add to group student_ids (trial != enrolled)
    await pool.query(
      `UPDATE leads SET status='Trial', group_id=$1, is_trial=TRUE WHERE id=$2`,
      [groupId, leadId]
    );
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get trial leads for a group
app.get('/api/groups/:id/trial-leads', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM leads WHERE group_id=$1 AND status='Trial' ORDER BY created_at ASC`,
      [req.params.id]
    );
    res.json(rows.map(l => ({
      id: l.id, firstName: l.first_name, lastName: l.last_name,
      phoneStudent: l.phone_student, phoneFather: l.phone_father,
      currentLevel: l.current_level, status: l.status,
      groupId: l.group_id, isTrial: true
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/leads/:id/to-payment', async (req, res) => {
  try {
    await pool.query(`UPDATE leads SET status='Payment' WHERE id=$1`, [req.params.id]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX: convert uses ON CONFLICT to safely upsert student
app.post('/api/leads/:id/convert', async (req, res) => {
  try {
    const lead = await pool.query('SELECT * FROM leads WHERE id=$1', [req.params.id]);
    if (!lead.rows[0]) return res.status(404).json({ error: 'Lead not found' });
    const l = lead.rows[0];
    if (l.status === 'Student') return res.json({ ok: true, alreadyConverted: true });
    const phone = l.phone_student || l.phone_father || l.phone_mother || l.phone_other || null;
    // Students use random unique 5-digit numeric IDs, not the lead's id
    let studentId;
    do {
      studentId = String(Math.floor(10000 + Math.random() * 90000));
      var existing = await pool.query('SELECT 1 FROM students WHERE id=$1', [studentId]);
    } while (existing.rows.length > 0);
    await pool.query(
      `INSERT INTO students(id,first_name,last_name,phone,level,status)
       VALUES($1,$2,$3,$4,$5,'Active')`,
      [studentId, l.first_name, l.last_name, phone, l.current_level]
    );
    await pool.query(`UPDATE leads SET status='Student' WHERE id=$1`, [req.params.id]);
    const actor = req.user ? req.user.first_name + ' ' + req.user.last_name : null;
    await pool.query(
      `INSERT INTO lead_conversions(lead_id, student_id, converted_by) VALUES($1,$2,$3)`,
      [req.params.id, studentId, actor]
    ).catch(()=>{});
    // Add to group student_ids now that they are a real student
    if (l.group_id) {
      const grp = await pool.query('SELECT student_ids FROM groups WHERE id=$1', [l.group_id]);
      if (grp.rows[0]) {
        const ids = grp.rows[0].student_ids || [];
        if (!ids.includes(studentId)) {
          ids.push(studentId);
          await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(ids), l.group_id]);
        }
      }
    }
    broadcast('leads');
    broadcast('students');
    res.json({ ok: true, studentId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leads/:id', async (req, res) => {
  try {
    const { reason, comment } = req.body || {};
    const { rows: cur } = await pool.query('SELECT status FROM leads WHERE id=$1', [req.params.id]);
    const preStatus = cur[0]?.status || null;
    await pool.query(
      `UPDATE leads SET archived=TRUE, archive_reason=$1, archive_comment=$2, archived_at=NOW(), pre_archive_status=$3 WHERE id=$4`,
      [reason||null, comment||null, preStatus, req.params.id]
    );
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leads/:id/permanent', async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query('DELETE FROM leads WHERE id=$1', [id]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/leads/:id/restore', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT pre_archive_status FROM leads WHERE id=$1', [req.params.id]);
    const status = rows[0]?.pre_archive_status || 'Registration';
    await pool.query(
      `UPDATE leads SET archived=FALSE, archive_reason=NULL, archive_comment=NULL, archived_at=NULL, pre_archive_status=NULL, status=$1 WHERE id=$2`,
      [status, req.params.id]
    );
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* LEAD CONVERSIONS */
app.get('/api/lead-conversions', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT lc.*, l.first_name||' '||l.last_name AS lead_name
       FROM lead_conversions lc
       LEFT JOIN leads l ON l.id = lc.lead_id
       ORDER BY lc.converted_at DESC
       LIMIT 100`
    );
    res.json(rows.map(r => ({
      id: r.id, leadId: r.lead_id, leadName: r.lead_name,
      studentId: r.student_id, convertedBy: r.converted_by,
      convertedAt: r.converted_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* LEAD CALLS */
app.get('/api/leads/:id/calls', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM lead_calls WHERE lead_id=$1 ORDER BY created_at DESC', [req.params.id]);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/leads/:id/calls', async (req, res) => {
  try {
    const { note, actor } = req.body;
    await pool.query('INSERT INTO lead_calls(lead_id,note,actor) VALUES($1,$2,$3)', [req.params.id, note, actor||null]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/leads/calls/:callId', async (req, res) => {
  try {
    await pool.query('DELETE FROM lead_calls WHERE id=$1', [req.params.callId]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* DASHBOARD — one aggregated payload (stats + timetable) */
app.get('/api/dashboard', async (req, res) => {
  try {
    const me = req.user;
    const teacher = isTeacherTitle(me.title);
    const myName = (me.first_name + ' ' + me.last_name);
    const today = new Date(new Date().toLocaleString('en-US', { timeZone:'Asia/Tashkent' }))
      .toISOString().split('T')[0];

    const [grpR, stuR, invR, leadR, attR] = await Promise.all([
      pool.query('SELECT id,name,teacher,room,level,lang,time,duration,sched_type,custom_days,current_unit,student_ids FROM groups ORDER BY created_at DESC'),
      pool.query("SELECT id,status,balance FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial')"),
      pool.query("SELECT COUNT(*)::int n FROM invoices WHERE status='Paid'"),
      pool.query('SELECT status, COUNT(*)::int n FROM leads GROUP BY status'),
      pool.query("SELECT group_id, student_id FROM attendance WHERE date=$1 AND status='absent'", [today]),
    ]);

    const enrolledAll = new Set(grpR.rows.flatMap(g => g.student_ids || []));
    let groups = grpR.rows;
    if (teacher) groups = groups.filter(g => (g.teacher || '') === myName);
    const scopeIds = new Set(groups.flatMap(g => g.student_ids || []));
    const stuById = new Map(stuR.rows.map(s => [s.id, s]));

    const inScope = s => !teacher || scopeIds.has(s.id);
    const students = stuR.rows.filter(inScope);
    const activeStudents = students.filter(s => enrolledAll.has(s.id) && s.status === 'Active').length;
    const debtors = students.filter(s => Number(s.balance || 0) < 0).length;
    const leadCount = leadR.rows.filter(r => r.status==='Registration'||r.status==='Waitlist').reduce((a,r)=>a+r.n,0);
    const trial = leadR.rows.filter(r => r.status==='Trial').reduce((a,r)=>a+r.n,0);
    const absentIds = new Set();
    const ownGrp = new Set(groups.map(g=>g.id));
    attR.rows.forEach(r => { if (!teacher || ownGrp.has(r.group_id)) absentIds.add(r.student_id); });

    res.json({
      stats: { activeStudents, debtors, paidCount: invR.rows[0].n, leads: leadCount, trial, absentToday: absentIds.size },
      groups: groups.map(g => ({
        id: g.id, name: g.name, teacher: g.teacher, room: g.room, level: g.level, lang: g.lang,
        time: g.time, duration: g.duration, schedType: g.sched_type, customDays: g.custom_days,
        currentUnit: g.current_unit || '1A',
        enrolledCount: (g.student_ids || []).filter(id => stuById.has(id)).length
      }))
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* REMINDERS */
function autoMarkOverdue(rows) {
  const now = new Date();
  return rows.map(r => {
    if (['pending','in_process'].includes(r.status) && r.due_date) {
      const timeStr = r.due_time ? r.due_time.slice(0,5) : '23:59';
      const due = new Date(`${r.due_date.toISOString().slice(0,10)}T${timeStr}:00+05:00`);
      if (due < now) r.status = 'overdue';
    }
    return r;
  });
}

app.get('/api/reminders', async (req, res) => {
  try {
    const me = req.user;
    // Auto-mark overdue in DB first
    await pool.query(`
      UPDATE reminders SET status='overdue'
      WHERE status IN ('pending','in_process') AND due_date IS NOT NULL
        AND (due_date::text || ' ' || COALESCE(due_time::text,'23:59:00'))::timestamp
            < NOW() AT TIME ZONE 'Asia/Tashkent'
    `).catch(()=>{});
    const myRolesGet = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    const isAdminRole = myRolesGet.some(r => ['admin','head admin','manager'].includes(r));
    const { rows } = await pool.query(
      `SELECT r.*,
        cu.first_name||' '||cu.last_name AS created_by_name,
        CASE WHEN r.assigned_to_id='administration' THEN 'Administration'
             ELSE au.first_name||' '||au.last_name END AS assigned_to_name
       FROM reminders r
       LEFT JOIN users cu ON cu.id = r.created_by_id
       LEFT JOIN users au ON au.id = r.assigned_to_id
       WHERE r.assigned_to_id=$1 OR r.created_by_id=$1
          OR (r.assigned_to_id='administration' AND $2)
       ORDER BY
         CASE r.status WHEN 'overdue' THEN 0 WHEN 'pending' THEN 1 WHEN 'in_process' THEN 2 ELSE 3 END,
         r.due_date ASC NULLS LAST, r.created_at DESC`,
      [me.id, isAdminRole]);
    res.json(rows.map(r => ({
      id: r.id, title: r.title, note: r.note,
      dueDate: r.due_date, dueTime: r.due_time, priority: r.priority,
      status: r.status || 'pending', createdAt: r.created_at,
      createdById: r.created_by_id, createdByName: r.created_by_name,
      assignedToId: r.assigned_to_id, assignedToName: r.assigned_to_name,
      repeatEvery: r.repeat_every || null,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reminders/count', async (req, res) => {
  try {
    const cRoles = (req.user.roles||[req.user.title||'']).map(r=>String(r).trim().toLowerCase());
    const cIsAdmin = cRoles.some(r=>['admin','head admin','manager'].includes(r));
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS n FROM reminders
       WHERE (assigned_to_id=$1 OR (assigned_to_id='administration' AND $2))
         AND status NOT IN ('completed')`,
      [req.user.id, cIsAdmin]
    );
    res.json({ count: rows[0].n });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reminders/all', async (req, res) => {
  try {
    const me = req.user;
    const roles = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    if (!roles.some(r=>['ceo','manager','head admin'].includes(r)))
      return res.status(403).json({ error: 'Access denied.' });
    await pool.query(`
      UPDATE reminders SET status='overdue'
      WHERE status IN ('pending','in_process') AND due_date IS NOT NULL
        AND (due_date::text || ' ' || COALESCE(due_time::text,'23:59:00'))::timestamp
            < NOW() AT TIME ZONE 'Asia/Tashkent'
    `).catch(()=>{});
    const { rows } = await pool.query(
      `SELECT r.*,
        cu.first_name||' '||cu.last_name AS created_by_name,
        CASE WHEN r.assigned_to_id='administration' THEN 'Administration'
             ELSE au.first_name||' '||au.last_name END AS assigned_to_name
       FROM reminders r
       LEFT JOIN users cu ON cu.id = r.created_by_id
       LEFT JOIN users au ON au.id = r.assigned_to_id
       ORDER BY
         CASE r.status WHEN 'overdue' THEN 0 WHEN 'pending' THEN 1 WHEN 'in_process' THEN 2 ELSE 3 END,
         r.due_date ASC NULLS LAST, r.created_at DESC`
    );
    res.json(rows.map(r => ({
      id: r.id, title: r.title, note: r.note,
      dueDate: r.due_date, dueTime: r.due_time, priority: r.priority,
      status: r.status || 'pending', createdAt: r.created_at,
      createdById: r.created_by_id, createdByName: r.created_by_name,
      assignedToId: r.assigned_to_id, assignedToName: r.assigned_to_name,
      repeatEvery: r.repeat_every || null,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reminders', async (req, res) => {
  try {
    const me = req.user;
    const { id, title, note, dueDate, dueTime, priority, assignedToId, repeatEvery } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required.' });
    const finalAssignee = assignedToId || me.id;
    await pool.query(
      `INSERT INTO reminders(id,title,note,due_date,due_time,priority,created_by_id,assigned_to_id,status,repeat_every)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)`,
      [id, title, note||null, dueDate||null, dueTime||null, priority||'medium', me.id, finalAssignee, repeatEvery||null]
    );
    if (finalAssignee === 'administration') {
      const { rows: admins } = await pool.query(
        `SELECT id FROM users WHERE (title IN ('Admin','Head Admin','Manager') OR roles @> '["Admin"]'::jsonb OR roles @> '["Head Admin"]'::jsonb OR roles @> '["Manager"]'::jsonb) AND id<>$1`,
        [me.id]
      ).catch(()=>({rows:[]}));
      for (const u of admins) await createNotif(u.id, 'task_assigned', 'New task for Administration',
        `"${title}" assigned by ${me.first_name} ${me.last_name}`, 'reminders.html');
    } else if (finalAssignee !== me.id) {
      await createNotif(finalAssignee, 'task_assigned', 'New task assigned to you',
        `"${title}" assigned by ${me.first_name} ${me.last_name}`, 'reminders.html');
    }
    broadcast('reminders');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Advance status: only assignee can do this; overdue locked except CEO
app.put('/api/reminders/:id/status', async (req, res) => {
  try {
    const me = req.user;
    const myRoles = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    const isCEO = myRoles.includes('ceo');
    const { status } = req.body;
    const allowed = ['pending','in_process','completed'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    // Check current status
    const { rows } = await pool.query(`SELECT status, assigned_to_id FROM reminders WHERE id=$1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found.' });
    const task = rows[0];
    const statusRoles = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    const isAdminUser = statusRoles.some(r=>['admin','head admin','manager'].includes(r));
    const isAdminTask = task.assigned_to_id === 'administration';
    if (task.status === 'overdue' && !isCEO) return res.status(403).json({ error: 'Overdue tasks are locked.' });
    if (!isAdminTask && task.assigned_to_id !== me.id && !isCEO)
      return res.status(403).json({ error: 'Only assignee can update status.' });
    if (isAdminTask && !isAdminUser && !isCEO)
      return res.status(403).json({ error: 'Only Admin/Head Admin/Manager can update this task.' });
    const { rows: tr } = await pool.query(`SELECT title, created_by_id, due_date, due_time, priority, assigned_to_id, repeat_every, note FROM reminders WHERE id=$1`, [req.params.id]);
    // Claim administration task when moving to in_process
    if (isAdminTask && status === 'in_process') {
      await pool.query(`UPDATE reminders SET status=$1, assigned_to_id=$2 WHERE id=$3`, [status, me.id, req.params.id]);
    } else {
      await pool.query(`UPDATE reminders SET status=$1 WHERE id=$2`, [status, req.params.id]);
    }
    if (tr.length && tr[0].created_by_id !== me.id) {
      const statusLabel = { in_process:'In Process', completed:'Completed' }[status] || status;
      await createNotif(tr[0].created_by_id, 'task_status', 'Task status updated',
        `"${tr[0].title}" marked as ${statusLabel} by ${me.first_name} ${me.last_name}`, 'reminders.html');
    }
    // Spawn next occurrence if recurring and just completed
    if (status === 'completed' && tr.length && tr[0].repeat_every && tr[0].due_date) {
      const t = tr[0];
      const DAYS = { daily:1, weekly:7, biweekly:14, monthly:30 };
      const delta = DAYS[t.repeat_every];
      if (delta) {
        const nextDate = new Date(t.due_date);
        nextDate.setDate(nextDate.getDate() + delta);
        const nextIso = nextDate.toISOString().split('T')[0];
        const newId = require('crypto').randomUUID();
        await pool.query(
          `INSERT INTO reminders(id,title,note,due_date,due_time,priority,created_by_id,assigned_to_id,status,repeat_every)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)`,
          [newId, t.title, t.note||null, nextIso, t.due_time||null, t.priority||'medium', t.created_by_id, t.assigned_to_id, t.repeat_every]
        );
      }
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/reminders/:id', async (req, res) => {
  try {
    const me = req.user;
    const myRoles = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    const isCEO = myRoles.includes('ceo');
    const { title, note, dueDate, dueTime, priority, assignedToId, repeatEvery } = req.body;
    // Check if overdue
    const { rows } = await pool.query(`SELECT status, created_by_id FROM reminders WHERE id=$1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found.' });
    if (rows[0].status === 'overdue' && !isCEO) return res.status(403).json({ error: 'Overdue tasks cannot be edited.' });
    if (rows[0].created_by_id !== me.id && !isCEO) return res.status(403).json({ error: 'Not allowed.' });
    await pool.query(
      `UPDATE reminders SET title=$1,note=$2,due_date=$3,due_time=$4,priority=$5,assigned_to_id=$6,repeat_every=$7 WHERE id=$8`,
      [title, note||null, dueDate||null, dueTime||null, priority||'medium', assignedToId, repeatEvery||null, req.params.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/reminders/:id', async (req, res) => {
  try {
    const me = req.user;
    const myRoles = (me.roles||[me.title||'']).map(r=>String(r).trim().toLowerCase());
    const isCEO = myRoles.includes('ceo');
    const { rows } = await pool.query(`SELECT status, created_by_id FROM reminders WHERE id=$1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found.' });
    if (rows[0].status === 'overdue' && !isCEO) return res.status(403).json({ error: 'Overdue tasks can only be deleted by CEO.' });
    if (rows[0].created_by_id !== me.id && !isCEO) return res.status(403).json({ error: 'Not allowed.' });
    await pool.query(`DELETE FROM reminders WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* NOTIFICATIONS */
app.get('/api/notifications', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM notifications WHERE recipient_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json(rows.map(n => ({
      id: n.id, type: n.type, title: n.title, body: n.body,
      link: n.link, read: n.read, createdAt: n.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications/count', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS n FROM notifications WHERE recipient_id=$1 AND read=FALSE`,
      [req.user.id]
    );
    res.json({ count: rows[0].n });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/notifications/read-all', async (req, res) => {
  try {
    await pool.query(`UPDATE notifications SET read=TRUE WHERE recipient_id=$1`, [req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/notifications/:id/read', async (req, res) => {
  try {
    await pool.query(`UPDATE notifications SET read=TRUE WHERE id=$1 AND recipient_id=$2`, [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* MEMBERS — lightweight user list for task assignment, accessible to all authenticated users */
app.get('/api/members', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, first_name, last_name, title FROM users ORDER BY first_name');
    res.json(rows.map(u => ({ id: u.id, name: u.first_name+' '+u.last_name, title: u.title })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ACTIVITY */
app.get('/api/activity', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 500;
    const { rows } = await pool.query('SELECT * FROM activity ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(rows.map(a => ({
      text: a.text, color: a.color, actor: a.actor, role: a.role,
      time: new Date(a.created_at).toLocaleString('en-GB', { timeZone:'Asia/Tashkent', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:false })
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/activity', async (req, res) => {
  try {
    const { text, color, actor, role } = req.body;
    await pool.query('INSERT INTO activity(text,color,actor,role) VALUES($1,$2,$3,$4)', [text, color||null, actor||null, role||null]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/statistics', async (req, res) => {
  try {
    const callerRoles_ = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
    if (!callerRoles_.includes('CEO')) return res.status(403).json({ error: 'CEO only.' });

    const now = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    const prevMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().split('T')[0];
    const prevMonthEnd = new Date(now.getFullYear(), now.getMonth(), 0).toISOString().split('T')[0];

    const [stuR, leadR, grpR, invR, usersR, archR, attR, supR, leadConvR, spendR] = await Promise.all([
      pool.query("SELECT id, status, balance FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial')"),
      pool.query('SELECT id, status, created_at FROM leads WHERE archived IS NOT TRUE'),
      pool.query('SELECT id, name, teacher, level, lang, student_ids FROM groups'),
      pool.query("SELECT id, total, status, payment_type, created_at, month FROM invoices ORDER BY created_at ASC"),
      pool.query('SELECT id, first_name, last_name, title, roles FROM users'),
      pool.query(`SELECT archive_reason FROM students WHERE archived IS TRUE
                  UNION ALL SELECT archive_reason FROM leads WHERE archived IS TRUE`),
      pool.query(`SELECT a.group_id, a.student_id, a.status, g.teacher
                  FROM attendance a JOIN groups g ON g.id=a.group_id
                  WHERE a.date >= $1`, [prevMonthStart]),
      pool.query(`SELECT teacher, attended, date FROM support_sessions WHERE date >= $1`, [prevMonthStart]),
      pool.query(`SELECT created_at FROM leads WHERE status='Registration' OR (archived IS TRUE AND pre_archive_status='Registration')`),
      pool.query(`SELECT amount, month, created_at FROM spendings ORDER BY created_at ASC`),
    ]);

    const students = stuR.rows;
    const leads = leadR.rows;
    const groups = grpR.rows;
    const invoices = invR.rows;
    const users = usersR.rows;

    // ── Students ──
    const activeStudents = students.filter(s => s.status === 'Active').length;
    const debtors = students.filter(s => Number(s.balance || 0) < 0).length;
    const totalBalance = students.reduce((sum, s) => sum + Number(s.balance || 0), 0);

    // ── Leads funnel ──
    const FUNNEL_ORDER = ['New','Contacted','Trial','Registration','Waitlist'];
    const leadsByStatus = {};
    leads.forEach(l => { leadsByStatus[l.status] = (leadsByStatus[l.status] || 0) + 1; });
    const totalLeads = leads.length;
    const registeredLeads = leadConvR.rows.length;
    const conversionRate = totalLeads > 0 ? Math.round(registeredLeads / (totalLeads + registeredLeads) * 100) : 0;
    const leadsThisMonth = leads.filter(l => l.created_at && l.created_at.toISOString().slice(0,7) === now.toISOString().slice(0,7)).length;

    // ── Finance ──
    const paidInvoices = invoices.filter(i => i.status === 'Paid');
    const totalRevenue = paidInvoices.reduce((sum, i) => sum + Number(i.total || 0), 0);
    const pendingRevenue = invoices.filter(i => i.status === 'Pending').reduce((sum, i) => sum + Number(i.total || 0), 0);
    const revenueByMonth = {};
    paidInvoices.forEach(i => {
      const key = i.month || (i.created_at ? i.created_at.toISOString().slice(0, 7) : null);
      if (key) revenueByMonth[key] = (revenueByMonth[key] || 0) + Number(i.total || 0);
    });
    const revenueByType = {};
    paidInvoices.forEach(i => { const k = i.payment_type || 'Cash'; revenueByType[k] = (revenueByType[k] || 0) + Number(i.total || 0); });

    // Spendings by month
    const spendingByMonth = {};
    spendR.rows.forEach(s => {
      const key = s.month || (s.created_at ? s.created_at.toISOString().slice(0, 7) : null);
      if (key) spendingByMonth[key] = (spendingByMonth[key] || 0) + Number(s.amount || 0);
    });
    const totalSpendings = spendR.rows.reduce((sum, s) => sum + Number(s.amount || 0), 0);

    const thisMonthRevenue = paidInvoices.filter(i => {
      const key = i.month || (i.created_at ? i.created_at.toISOString().slice(0, 7) : '');
      return key === now.toISOString().slice(0, 7);
    }).reduce((sum, i) => sum + Number(i.total || 0), 0);
    const prevMonthRevenue = paidInvoices.filter(i => {
      const key = i.month || (i.created_at ? i.created_at.toISOString().slice(0, 7) : '');
      return key === prevMonthStart.slice(0, 7);
    }).reduce((sum, i) => sum + Number(i.total || 0), 0);

    // ── Staff efficiency ──
    const teacherMap = {};
    groups.forEach(g => {
      if (!g.teacher) return;
      if (!teacherMap[g.teacher]) teacherMap[g.teacher] = { groups: 0, students: 0, present: 0, absent: 0 };
      teacherMap[g.teacher].groups++;
      teacherMap[g.teacher].students += (g.student_ids || []).length;
    });
    attR.rows.forEach(a => {
      const t = a.teacher;
      if (!t || !teacherMap[t]) return;
      if (a.status === 'present') teacherMap[t].present++;
      else if (a.status === 'absent') teacherMap[t].absent++;
    });

    const supMap = {};
    supR.rows.forEach(s => {
      if (!s.teacher) return;
      if (!supMap[s.teacher]) supMap[s.teacher] = { total: 0, attended: 0 };
      supMap[s.teacher].total++;
      if (s.attended) supMap[s.teacher].attended++;
    });

    const teacherStats = Object.entries(teacherMap).map(([name, d]) => {
      const total = d.present + d.absent;
      return { name, groups: d.groups, students: d.students, attendanceRate: total > 0 ? Math.round(d.present / total * 100) : null, sessions: total };
    }).sort((a, b) => b.students - a.students);

    const supportStats = Object.entries(supMap).map(([name, d]) => ({
      name, total: d.total, attended: d.attended,
      rate: d.total > 0 ? Math.round(d.attended / d.total * 100) : null
    })).sort((a, b) => b.total - a.total);

    const archiveByReason = {};
    archR.rows.forEach(a => { const k = a.archive_reason || 'Other'; archiveByReason[k] = (archiveByReason[k] || 0) + 1; });

    res.json({
      students: { total: students.length, active: activeStudents, inactive: students.length - activeStudents, debtors, totalBalance },
      leads: { total: totalLeads, byStatus: leadsByStatus, conversionRate, leadsThisMonth, funnelOrder: FUNNEL_ORDER },
      finance: { totalRevenue, pendingRevenue, revenueByMonth, revenueByType, thisMonthRevenue, prevMonthRevenue, paidCount: paidInvoices.length, pendingByMonth: (() => { const m={}; invoices.filter(i=>i.status==='Pending').forEach(i=>{ const k=i.month||(i.created_at?i.created_at.toISOString().slice(0,7):null); if(k) m[k]=(m[k]||0)+Number(i.total||0); }); return m; })(), spendingByMonth, totalSpendings },
      staff: { teachers: teacherStats, support: supportStats, total: users.length },
      archive: { total: archR.rows.length, byReason: archiveByReason },
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

const PORT = process.env.PORT || 3000;
initDB().then(() => app.listen(PORT, () => {
  console.log(`TommyLC running on port ${PORT}`);

  // Monthly auto-charge: runs at 00:01 on the 1st of every month (Tashkent time)
  cron.schedule('1 0 1 * *', async () => {
    try {
      await runMonthlyCharge();
    } catch(e) {
      console.error('[Monthly charge] Error:', e.message);
    }
  }, { timezone: 'Asia/Tashkent' });
}));

async function runMonthlyCharge() {
  const now = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
  const monthStr = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');

  const { rows: activeStudents } = await pool.query(
    `SELECT * FROM students WHERE status='Active' AND (archived IS NULL OR archived=FALSE)`
  );
  const { rows: allGroups } = await pool.query(
    `SELECT id, name, level, price, student_ids FROM groups`
  );
  const { rows: pricing } = await pool.query('SELECT * FROM pricing');
  const priceMap = {};
  pricing.forEach(p => { priceMap[p.level] = Number(p.price); });

  let processed = 0, skipped = 0, errors = 0;

  for (const s of activeStudents) {
    try {
      // Find all groups this student is enrolled in
      const studentGroups = allGroups.filter(g => (g.student_ids || []).includes(s.id));

      // Determine charges: one per group (using group price), or fall back to level price once
      let charges = [];
      if (studentGroups.length > 0) {
        for (const g of studentGroups) {
          const groupPrice = Math.abs(Number(g.price || 0));
          const levelPrice = Math.abs(priceMap[g.level] || priceMap[s.level] || 0);
          const price = groupPrice || levelPrice;
          if (price > 0) charges.push({ price, groupId: g.id, groupName: g.name });
        }
      } else {
        // Student not in any group — use their level price
        const price = Math.abs(priceMap[s.level] || 0);
        if (price > 0) charges.push({ price, groupId: null, groupName: null });
      }

      if (!charges.length) { skipped++; continue; }

      for (const charge of charges) {
        const existing = await pool.query(
          `SELECT id FROM invoices WHERE student_id=$1 AND month=$2 AND payment_type='Auto' AND group_id IS NOT DISTINCT FROM $3`,
          [s.id, monthStr, charge.groupId || null]
        );
        if (existing.rows.length > 0) continue;

        const invId  = 'inv-' + Date.now() + '-' + Math.random().toString(36).slice(2,6);
        const invNum = 'INV-' + Date.now().toString().slice(-6);
        const desc   = charge.groupName
          ? `Monthly charge — ${charge.groupName} (${monthStr})`
          : `Monthly charge — ${monthStr}`;
        await pool.query(
          `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type)
           VALUES($1,$2,$3,$4,$5,$6,$7,'Pending','Auto')`,
          [invId, invNum, s.id, charge.groupId, monthStr, desc, charge.price]
        );
        await pool.query(
          'UPDATE students SET balance=balance-$1 WHERE id=$2',
          [charge.price, s.id]
        );
        processed++;
      }
    } catch(e) {
      console.error(`[Monthly charge] Error for student ${s.id}:`, e.message);
      errors++;
    }
  }

  // Persist last run timestamp and result
  await pool.query(
    `INSERT INTO app_config(key,value) VALUES('monthly_charge_last_run',$1) ON CONFLICT(key) DO UPDATE SET value=$1`,
    [JSON.stringify({ month: monthStr, processed, skipped, errors, ts: new Date().toISOString() })]
  ).catch(()=>{});

  console.log(`[Monthly charge] Processed ${processed}, skipped ${skipped}, errors ${errors} for ${monthStr}`);
  return { processed, skipped, errors, month: monthStr };
}

