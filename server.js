const express  = require('express');
const { Pool } = require('pg');
const path     = require('path');
const cors     = require('cors');
const cron     = require('node-cron');
const crypto   = require('crypto');
const compression = require('compression');

const app  = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(compression());
app.use(cors());
app.use(express.json());

/* ══════════════════════════════════════
   PERMISSIONS
══════════════════════════════════════ */
// Page permissions: having one = full see + manage of that section.
const PAGE_PERMISSIONS = ['dashboard','leads','students','groups','finance','teachers','staff','actions','classrooms','archived'];
// finance_view_only restricts Finance to read (no recording/editing).
const ALL_PERMISSIONS = [...PAGE_PERMISSIONS, 'finance_view_only'];

// Fixed roles → permission sets. These are the only assignable titles.
const ROLE_PERMS = {
  'CEO':        [...PAGE_PERMISSIONS],
  'Head Admin': ['dashboard','leads','students','groups','finance','teachers','classrooms','archived','finance_view_only'],
  'Manager':    ['dashboard','leads','students','groups','finance','teachers','staff','classrooms','archived'],
  'Admin':      ['dashboard','leads','students','groups','teachers'],
  'Teacher':    ['dashboard','students','groups'],
  'Support Teacher': ['dashboard'],
};
function isSupportTitle(t) { return String(t||'').trim().toLowerCase() === 'support teacher'; }
const ROLES = Object.keys(ROLE_PERMS);
function permsForRole(title) { return (ROLE_PERMS[title] || ['dashboard']).slice(); }
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
    if (/\.(woff2?|ttf|png|jpg|jpeg|svg|ico)$/.test(fp)) res.setHeader('Cache-Control', 'public, max-age=86400');
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

    CREATE TABLE IF NOT EXISTS classrooms (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL UNIQUE,
      capacity    INTEGER,
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
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_parent TEXT`,
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
    `CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)`,
    `CREATE TABLE IF NOT EXISTS support_sessions (id TEXT PRIMARY KEY, date DATE, time TEXT, duration INT DEFAULT 30, teacher TEXT, student_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_invoices_student ON invoices(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_comments_student ON student_comments(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_calls_student ON student_calls(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_attendance_grp_date ON attendance(group_id, date)`,
    `CREATE INDEX IF NOT EXISTS idx_groups_student_ids ON groups USING gin (student_ids)`,
  ];
  for (const sql of alters) {
    await pool.query(sql).catch(() => {});
  }

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

  await loadAppSecret();
  console.log('Database ready');
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
  if (top === 'classrooms') return write ? 'classrooms' : null;
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
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : (req.headers['x-auth-token'] || '');
    const userId = token && verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Not authenticated' });
    const r = await pool.query('SELECT id, first_name, last_name, role, title, permissions FROM users WHERE id=$1', [userId]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Session no longer valid' });
    req.user = r.rows[0];
    const perms = req.user.permissions || [];
    const p = req.path.replace(/^\//, '');
    const write = req.method !== 'GET';
    const top = p.split('/').filter(Boolean)[0];

    // Teacher accounts: read-only everywhere; only attendance, activity log, and their own
    // account (e.g. first-login password change) may be written.
    if (isTeacherTitle(req.user.title)) {
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
// Support-teacher shift fields, only meaningful when title === 'Support Teacher'.
function supportShift(body, title) {
  if (!isSupportTitle(title)) return { start:null, end:null, days:null };
  const days = ['odd','even','daily'].includes(body.supportDays) ? body.supportDays : 'daily';
  return { start: body.supportStart || '09:00', end: body.supportEnd || '18:00', days };
}

app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at');
    res.json(rows.map(u => ({
      id: u.id, firstName: u.first_name, lastName: u.last_name,
      name: u.first_name+' '+u.last_name, phone: u.phone,
      role: u.role, title: u.title || u.role, avatar: u.avatar,
      permissions: u.permissions || [],
      supportStart: u.support_start, supportEnd: u.support_end, supportDays: u.support_days
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', async (req, res) => {
  try {
    const { id, firstName, lastName, phone, password, title } = req.body;
    if (!ROLE_PERMS[title]) return res.status(400).json({ error: 'Invalid role' });
    const pwErr = validateCreatePassword(password);
    if (pwErr) return res.status(400).json({ error: pwErr });
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    const perms = permsForRole(title);
    const sh = supportShift(req.body, title);
    await pool.query(
      'INSERT INTO users(id,first_name,last_name,phone,password,role,title,avatar,permissions,must_change_password,support_start,support_end,support_days) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,$10,$11,$12)',
      [id, firstName, lastName, phone, password, title, title, avatar, JSON.stringify(perms), sh.start, sh.end, sh.days]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, password, title } = req.body;
    if (!ROLE_PERMS[title]) return res.status(400).json({ error: 'Invalid role' });
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    const perms = permsForRole(title);
    const sh = supportShift(req.body, title);
    if (password) {
      const pwErr = validateCreatePassword(password);
      if (pwErr) return res.status(400).json({ error: pwErr });
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,password=$4,role=$5,title=$5,avatar=$6,permissions=$7,must_change_password=TRUE,support_start=$8,support_end=$9,support_days=$10 WHERE id=$11',
        [firstName, lastName, phone, password, title, avatar, JSON.stringify(perms), sh.start, sh.end, sh.days, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,role=$4,title=$4,avatar=$5,permissions=$6,support_start=$7,support_end=$8,support_days=$9 WHERE id=$10',
        [firstName, lastName, phone, title, avatar, JSON.stringify(perms), sh.start, sh.end, sh.days, req.params.id]
      );
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* STUDENTS */
app.get('/api/students', async (req, res) => {
  try {
    const [studRes, grpRes, cmtRes] = await Promise.all([
      pool.query('SELECT * FROM students WHERE archived IS NOT TRUE ORDER BY created_at DESC'),
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
        phone: s.phone, phoneParent: s.phone_parent,
        level: s.level,
        status: enrolled.has(s.id) ? s.status : 'Inactive',
        balance: Number(s.balance || 0),
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
    const { firstName, lastName, phone, phoneParent, level, status, exam, examDate, notes, school, grade, address } = req.body;
    let id;
    do {
      id = String(Math.floor(10000 + Math.random() * 90000));
      var existing = await pool.query('SELECT 1 FROM students WHERE id=$1', [id]);
    } while (existing.rows.length > 0);
    await pool.query(
      'INSERT INTO students(id,first_name,last_name,phone,phone_parent,level,status,exam,exam_date,notes,school,grade,address) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
      [id, firstName, lastName, phone||null, phoneParent||null, level||null, status||'Active', exam||null, examDate||null, notes||null, school||null, grade||null, address||null]
    );
    res.json({ ok: true, id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, phoneParent, level, status, exam, examDate, notes, school, grade, address } = req.body;
    await pool.query(
      'UPDATE students SET first_name=$1,last_name=$2,phone=$3,phone_parent=$4,level=$5,status=$6,exam=$7,exam_date=$8,notes=$9,school=$10,grade=$11,address=$12 WHERE id=$13',
      [firstName, lastName, phone||null, phoneParent||null, level||null, status||'Active', exam||null, examDate||null, notes||null, school||null, grade||null, address||null, req.params.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/students/:id', async (req, res) => {
  try {
    const { reason } = req.body || {};
    await pool.query(
      `UPDATE students SET archived=TRUE, archive_reason=$1, archived_at=NOW(), status='Inactive' WHERE id=$2`,
      [reason||null, req.params.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/students/archived', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM students WHERE archived=TRUE ORDER BY archived_at DESC`
    );
    res.json(rows.map(s => ({
      id: s.id, firstName: s.first_name, lastName: s.last_name,
      phone: s.phone, level: s.level, status: s.status,
      archiveReason: s.archive_reason,
      archivedAt: s.archived_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id/restore', async (req, res) => {
  try {
    await pool.query(
      `UPDATE students SET archived=FALSE, archive_reason=NULL, archived_at=NULL, status='Inactive' WHERE id=$1`,
      [req.params.id]
    );
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
      phone: s.phone, phoneParent: s.phone_parent,
      level: s.level, status: enr.rows.length ? s.status : 'Inactive', balance: Number(s.balance||0),
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
      const amount    = Math.round((monthlyPrice / 12) * remaining);

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

      return res.json({ ok: true, amount, remaining });
    }

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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/students/comments/:commentId', async (req, res) => {
  try {
    await pool.query('DELETE FROM student_comments WHERE id=$1', [req.params.commentId]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/students/calls/:callId', async (req, res) => {
  try {
    await pool.query('DELETE FROM student_calls WHERE id=$1', [req.params.callId]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* CLASSROOMS */
app.get('/api/classrooms', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM classrooms ORDER BY name');
    res.json(rows.map(r => ({ id: r.id, name: r.name })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/classrooms', async (req, res) => {
  try {
    const { id, name } = req.body;
    await pool.query('INSERT INTO classrooms(id,name) VALUES($1,$2)', [id, name]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/classrooms/:id', async (req, res) => {
  try {
    const { name } = req.body;
    const old = await pool.query('SELECT name FROM classrooms WHERE id=$1', [req.params.id]);
    if (old.rows[0] && old.rows[0].name !== name) {
      await pool.query('UPDATE groups SET room=$1 WHERE room=$2', [name, old.rows[0].name]);
    }
    await pool.query('UPDATE classrooms SET name=$1 WHERE id=$2', [name, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/classrooms/:id', async (req, res) => {
  try {
    const old = await pool.query('SELECT name FROM classrooms WHERE id=$1', [req.params.id]);
    if (old.rows[0]) {
      await pool.query('UPDATE groups SET room=NULL WHERE room=$1', [old.rows[0].name]);
    }
    await pool.query('DELETE FROM classrooms WHERE id=$1', [req.params.id]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM groups WHERE id=$1', [req.params.id]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/comments/:commentId', async (req, res) => {
  try {
    await pool.query('DELETE FROM group_comments WHERE id=$1', [req.params.commentId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/:id/students', async (req, res) => {
  try {
    const { studentIds } = req.body;
    const prev = await pool.query('SELECT student_ids FROM groups WHERE id=$1', [req.params.id]);
    const prevIds = prev.rows[0]?.student_ids || [];
    const newSet = new Set(studentIds || []);
    const removed = prevIds.filter(id => !newSet.has(id));
    await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(studentIds||[]), req.params.id]);
    // Auto-deactivate students no longer in any group
    if (removed.length) {
      const allGroups = await pool.query('SELECT student_ids FROM groups WHERE id!=$1', [req.params.id]);
      const stillEnrolled = new Set(allGroups.rows.flatMap(g => g.student_ids || []));
      for (const sid of removed) {
        if (!stillEnrolled.has(sid)) {
          await pool.query("UPDATE students SET status='Inactive' WHERE id=$1", [sid]);
        }
      }
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/:id/unit', async (req, res) => {
  try {
    const { unit } = req.body;
    await pool.query('UPDATE groups SET current_unit=$1 WHERE id=$2', [unit, req.params.id]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/invoices/:id/status', async (req, res) => {
  try {
    const { status, paymentType } = req.body;
    await pool.query('UPDATE invoices SET status=$1,payment_type=$2 WHERE id=$3', [status, paymentType||'Cash', req.params.id]);
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* SUPPORT SESSIONS — one-time lessons, one room, max 2 teachers at a time */
function toMin(t){ const [h,m]=String(t||'0:0').split(':').map(Number); return (h||0)*60+(m||0); }
function supportWorksOn(dateStr, days){ const dow=new Date(dateStr+'T00:00:00').getDay(); if(days==='odd')return [1,3,5].includes(dow); if(days==='even')return [2,4,6].includes(dow); return dow>=1&&dow<=6; }

app.get('/api/support-teachers', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT id, first_name, last_name, support_start, support_end, support_days FROM users WHERE title='Support Teacher' ORDER BY first_name");
    res.json(rows.map(u => ({ id: u.id, name: u.first_name+' '+u.last_name, start: u.support_start||'09:00', end: u.support_end||'18:00', days: u.support_days||'daily' })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/support/:date', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM support_sessions WHERE date=$1 ORDER BY time', [req.params.date]);
    res.json(rows.map(s => ({ id:s.id, date:s.date, time:s.time, duration:s.duration, teacher:s.teacher, studentId:s.student_id })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/support', async (req, res) => {
  try {
    const { id, date, time, duration, teacher, studentId } = req.body;
    if (!date || !time || !teacher || !studentId) return res.status(400).json({ error: 'Date, time, teacher and student are required.' });
    const dur = Number(duration) === 60 ? 60 : 30;
    const start = toMin(time), end = start + dur;
    // Enforce the teacher's working shift (days + hours).
    const tRes = await pool.query("SELECT support_start, support_end, support_days FROM users WHERE title='Support Teacher' AND (first_name||' '||last_name)=$1 LIMIT 1", [teacher]);
    const sh = tRes.rows[0];
    if (sh) {
      if (!supportWorksOn(date, sh.support_days||'daily')) return res.status(409).json({ error: 'This teacher does not work on this day.' });
      if (start < toMin(sh.support_start||'09:00') || end > toMin(sh.support_end||'18:00')) return res.status(409).json({ error: "Outside this teacher's working hours." });
    }
    const { rows } = await pool.query('SELECT * FROM support_sessions WHERE date=$1', [date]);
    const overlap = rows.filter(s => { const st=toMin(s.time), en=st+Number(s.duration||30); return start < en && st < end; });
    if (overlap.length >= 2) return res.status(409).json({ error: 'Both support slots are already taken at this time.' });
    if (overlap.some(s => s.teacher === teacher)) return res.status(409).json({ error: 'This teacher already has a session at this time.' });
    await pool.query(
      'INSERT INTO support_sessions(id,date,time,duration,teacher,student_id) VALUES($1,$2,$3,$4,$5,$6)',
      [id, date, time, dur, teacher, studentId]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/support/:id', async (req, res) => {
  try { await pool.query('DELETE FROM support_sessions WHERE id=$1', [req.params.id]); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
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
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* LEADS */
app.get('/api/leads', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM leads ORDER BY created_at DESC');
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
    res.json({ ok: true, studentId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leads/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM leads WHERE id=$1', [req.params.id]);
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

    const [grpR, stuR, invR, leadR, clsR, attR] = await Promise.all([
      pool.query('SELECT id,name,teacher,room,level,lang,time,duration,sched_type,custom_days,current_unit,student_ids FROM groups ORDER BY created_at DESC'),
      pool.query('SELECT id,status,balance FROM students WHERE archived IS NOT TRUE'),
      pool.query("SELECT COUNT(*)::int n FROM invoices WHERE status='Paid'"),
      pool.query('SELECT status, COUNT(*)::int n FROM leads GROUP BY status'),
      pool.query('SELECT id,name FROM classrooms ORDER BY name'),
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
      classrooms: clsR.rows.map(c => ({ id: c.id, name: c.name })),
      groups: groups.map(g => ({
        id: g.id, name: g.name, teacher: g.teacher, room: g.room, level: g.level, lang: g.lang,
        time: g.time, duration: g.duration, schedType: g.sched_type, customDays: g.custom_days,
        currentUnit: g.current_unit || '1A',
        enrolledCount: (g.student_ids || []).filter(id => stuById.has(id)).length
      }))
    });
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

  const { rows: pricing } = await pool.query('SELECT * FROM pricing');
  const priceMap = {};
  pricing.forEach(p => { priceMap[p.level] = Number(p.price); });

  let processed = 0, skipped = 0, errors = 0;

  for (const s of activeStudents) {
    try {
      const price = Math.abs(priceMap[s.level] || 0);
      if (!price) { skipped++; continue; }

      const existing = await pool.query(
        `SELECT id FROM invoices WHERE student_id=$1 AND month=$2 AND payment_type='Auto' AND description LIKE 'Monthly%'`,
        [s.id, monthStr]
      );
      if (existing.rows.length > 0) { skipped++; continue; }

      const invId  = 'inv-' + Date.now() + '-' + s.id.slice(-4);
      const invNum = 'INV-' + Date.now().toString().slice(-6);
      await pool.query(
        `INSERT INTO invoices(id,number,student_id,month,description,total,status,payment_type)
         VALUES($1,$2,$3,$4,$5,$6,'Pending','Auto')`,
        [invId, invNum, s.id, monthStr, `Monthly charge — ${monthStr}`, price]
      );
      await pool.query(
        'UPDATE students SET balance=balance-$1 WHERE id=$2',
        [price, s.id]
      );
      processed++;
    } catch(e) {
      console.error(`[Monthly charge] Error for student ${s.id}:`, e.message);
      errors++;
    }
  }

  console.log(`[Monthly charge] Processed ${processed}, skipped ${skipped}, errors ${errors} for ${monthStr}`);
  return { processed, skipped, errors, month: monthStr };
}

app.post('/api/admin/run-monthly-charge', async (req, res) => {
  try {
    const result = await runMonthlyCharge();
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});