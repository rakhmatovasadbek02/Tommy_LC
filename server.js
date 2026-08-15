const express  = require('express');
const { Pool } = require('pg');
const path     = require('path');
const cors     = require('cors');
const cron     = require('node-cron');
const crypto   = require('crypto');
const compression = require('compression');
const ExcelJS  = require('exceljs');

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

async function logStudentHistory(studentId, actor, actorRole, action, details = {}) {
  try {
    const id = 'sh_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
    await pool.query(
      `INSERT INTO student_history(id, student_id, actor, actor_role, action, details) VALUES($1,$2,$3,$4,$5,$6)`,
      [id, studentId, actor || 'System', actorRole || '', action, JSON.stringify(details)]
    );
  } catch(e) { console.warn('[history]', e.message); }
}

app.use(compression());
app.use(cors());
app.use(express.json());

/* ══════════════════════════════════════
   PERMISSIONS
══════════════════════════════════════ */
// Page permissions: having one = full see + manage of that section.
const PAGE_PERMISSIONS = ['dashboard','leads','students','groups','finance','teachers','staff','actions','archived','support','vocab'];
// finance_view_only restricts Finance to read (no recording/editing).
const ALL_PERMISSIONS = [...PAGE_PERMISSIONS, 'finance_view_only'];

// Fixed roles → permission sets. These are the only assignable titles.
const ROLE_PERMS = {
  'CEO':        [...PAGE_PERMISSIONS, 'statistics', 'manreminders', 'feedback'],
  'Head Admin': ['dashboard','leads','students','groups','finance','finance_view_only','teachers','staff','archived','support','vocab','reminders','manreminders'],
  'Manager':    ['dashboard','leads','students','groups','finance','teachers','staff','archived','support','vocab','reminders','manreminders'],
  'Admin':      ['dashboard','leads','students','groups','teachers','support','vocab','reminders'],
  'Teacher':    ['dashboard','groups','vocab','reminders'],
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

// "Pack" assignees (task can be assigned to a whole role group instead of one person).
// CEO sees/can claim every pack — same "full access" treatment CEO gets everywhere else.
const TASK_PACKS = {
  administration: { label: 'Administration', match: rolesLower => rolesLower.includes('ceo') || rolesLower.some(r => ['admin','head admin','manager'].includes(r)) },
  teachers:        { label: 'Teachers',       match: rolesLower => rolesLower.includes('ceo') || rolesLower.includes('teacher') },
  support:         { label: 'Support Teachers', match: rolesLower => rolesLower.includes('ceo') || rolesLower.includes('support teacher') },
};
function rolesLowerOf(user) { return (user.roles||[user.title||'']).map(r=>String(r).trim().toLowerCase()); }

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

    -- Suggestions/complaints students send from the student portal. Always routed to the
    -- CEO (via a notification, see notifyCEOs) — no other staff role can read these.
    CREATE TABLE IF NOT EXISTS student_feedback (
      id           TEXT PRIMARY KEY,
      student_id   TEXT NOT NULL,
      student_name TEXT NOT NULL,
      type         TEXT NOT NULL DEFAULT 'suggestion',
      message      TEXT NOT NULL,
      read         BOOLEAN DEFAULT FALSE,
      created_at   TIMESTAMPTZ DEFAULT NOW()
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

    -- Vocabulary test: units of words (a theme), plus one-time admin-granted access codes
    -- students use to take a test, plus a record of completed attempts.
    -- Each word carries all 3 languages (en/ru/uz); which pair a given test quizzes
    -- (RU-ENG or ENG-UZ) is chosen per grant, not baked into the unit.
    CREATE TABLE IF NOT EXISTS vocab_units (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      level         TEXT NOT NULL DEFAULT 'Elementary',
      words         JSONB NOT NULL DEFAULT '[]',
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS vocab_access (
      id            TEXT PRIMARY KEY,
      code          TEXT UNIQUE NOT NULL,
      student_id    TEXT NOT NULL,
      unit_ids      JSONB NOT NULL DEFAULT '[]',
      language_pair TEXT NOT NULL DEFAULT 'RU-ENG',
      granted_by    TEXT,
      question_set  JSONB,
      used          BOOLEAN DEFAULT FALSE,
      used_at       TIMESTAMPTZ,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS vocab_attempts (
      id          TEXT PRIMARY KEY,
      access_id   TEXT NOT NULL,
      student_id  TEXT NOT NULL,
      unit_ids    JSONB NOT NULL DEFAULT '[]',
      score       INT NOT NULL,
      total       INT NOT NULL,
      passed      BOOLEAN,
      answers     JSONB,
      completed_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Vocab tests can now cover multiple units per grant — migrate the old single unit_id
  // column to a unit_ids array (no real data existed under the old single-unit schema).
  await pool.query(`
    ALTER TABLE vocab_access  ADD COLUMN IF NOT EXISTS unit_ids JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE vocab_attempts ADD COLUMN IF NOT EXISTS unit_ids JSONB NOT NULL DEFAULT '[]';
  `).catch(() => {});
  await pool.query(`
    UPDATE vocab_access SET unit_ids = jsonb_build_array(unit_id) WHERE unit_id IS NOT NULL AND unit_ids = '[]'::jsonb
  `).catch(() => {});
  await pool.query(`
    UPDATE vocab_attempts SET unit_ids = jsonb_build_array(unit_id) WHERE unit_id IS NOT NULL AND unit_ids = '[]'::jsonb
  `).catch(() => {});
  await pool.query(`ALTER TABLE vocab_access DROP COLUMN IF EXISTS unit_id`).catch(() => {});
  await pool.query(`ALTER TABLE vocab_attempts DROP COLUMN IF EXISTS unit_id`).catch(() => {});

  // Units are now trilingual (en/ru/uz per word); the RU-ENG/ENG-UZ pair moved from the
  // unit to the access grant instead. No real unit data existed under the old shape.
  await pool.query(`ALTER TABLE vocab_units DROP COLUMN IF EXISTS language_pair`).catch(() => {});
  await pool.query(`ALTER TABLE vocab_access ADD COLUMN IF NOT EXISTS language_pair TEXT NOT NULL DEFAULT 'RU-ENG'`).catch(() => {});

  // Units are tagged with a course level (e.g. "Elementary") so Grant Access only offers
  // units matching the student's group level.
  await pool.query(`ALTER TABLE vocab_units ADD COLUMN IF NOT EXISTS level TEXT NOT NULL DEFAULT 'Elementary'`).catch(() => {});
  await pool.query(`ALTER TABLE vocab_attempts ADD COLUMN IF NOT EXISTS passed BOOLEAN`).catch(() => {});

  // student_history table (added as separate migration for safety)
  await pool.query(`CREATE TABLE IF NOT EXISTS student_history (
    id TEXT PRIMARY KEY,
    student_id TEXT NOT NULL,
    actor TEXT,
    actor_role TEXT,
    action TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  )`).catch(() => {});
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_student_history_student ON student_history(student_id)`).catch(() => {});

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
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS freeze_periods JSONB DEFAULT '[]'`,
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
    // Which language(s) a support teacher can take sessions in — 'UZ', 'RU', or 'UZ/RU'
    // (bilingual, available to any group). Defaults to bilingual so existing support
    // teachers stay bookable by everyone until an admin narrows it.
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS support_lang TEXT DEFAULT 'UZ/RU'`,
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
    `CREATE TABLE IF NOT EXISTS lead_containers (id TEXT PRIMARY KEY, status TEXT NOT NULL, name TEXT NOT NULL, collapsed BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_lead_calls ON lead_calls(lead_id)`,
    `CREATE TABLE IF NOT EXISTS lead_conversions (id SERIAL PRIMARY KEY, lead_id TEXT NOT NULL, student_id TEXT, converted_by TEXT, converted_at TIMESTAMPTZ DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_attendance_grp_date ON attendance(group_id, date)`,
    `CREATE INDEX IF NOT EXISTS idx_groups_student_ids ON groups USING gin (student_ids)`,
    `CREATE TABLE IF NOT EXISTS archive_reasons (id SERIAL PRIMARY KEY, label TEXT NOT NULL UNIQUE, is_blacklist BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW())`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS archive_comment TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS pre_archive_status TEXT`,
    // A single hidden test student (student portal QA) that must never count toward
    // real rosters/stats — see is_test filters on the admin student-list/dashboard/
    // statistics queries below.
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS is_test BOOLEAN DEFAULT FALSE`,
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

    // ── Student portal: self-service registration, vocab practice, support booking ──
    `CREATE TABLE IF NOT EXISTS student_portal_codes (
      id          TEXT PRIMARY KEY,
      code        TEXT UNIQUE NOT NULL,
      student_id  TEXT NOT NULL,
      used        BOOLEAN DEFAULT FALSE,
      used_at     TIMESTAMPTZ,
      granted_by  TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS student_logins (
      student_id  TEXT PRIMARY KEY,
      username    TEXT NOT NULL UNIQUE,
      password    TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Ephemeral holder for a generated practice question set (correct answers included) —
    // deleted once the student submits, so answers never sit around longer than needed.
    `CREATE TABLE IF NOT EXISTS vocab_practice_sessions (
      id            TEXT PRIMARY KEY,
      student_id    TEXT NOT NULL,
      unit_ids      JSONB NOT NULL DEFAULT '[]',
      language_pair TEXT NOT NULL DEFAULT 'RU-ENG',
      question_set  JSONB NOT NULL,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Free-practice history — separate from admin-graded vocab_attempts so it never
    // affects admin reporting on formal (code-granted) tests.
    `CREATE TABLE IF NOT EXISTS vocab_practice_attempts (
      id            TEXT PRIMARY KEY,
      student_id    TEXT NOT NULL,
      unit_ids      JSONB NOT NULL DEFAULT '[]',
      language_pair TEXT NOT NULL DEFAULT 'RU-ENG',
      score         INT NOT NULL,
      total         INT NOT NULL,
      passed        BOOLEAN,
      completed_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_student_portal_codes_student ON student_portal_codes(student_id)`,
    `CREATE INDEX IF NOT EXISTS idx_vocab_practice_attempts_student ON vocab_practice_attempts(student_id)`,
    // Login moved from phone number to a student-chosen username — rename in place for
    // any database that already created the table under the old shape.
    `ALTER TABLE student_logins RENAME COLUMN phone TO username`,
    `ALTER TABLE student_logins ADD CONSTRAINT student_logins_username_key UNIQUE (username)`,
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

  // Sync Head Admin permissions: finance view-only, staff, support, manreminders — remove full finance write.
  try {
    const headAdmins = await pool.query(`SELECT id, permissions FROM users WHERE title='Head Admin' OR roles @> '["Head Admin"]'::jsonb`);
    for (const u of headAdmins.rows) {
      let perms = Array.isArray(u.permissions) ? u.permissions : [];
      // Remove actions/statistics (not for Head Admin); ensure finance is present but view-only
      perms = perms.filter(p => !['actions','statistics'].includes(p));
      for (const p of ['finance','finance_view_only','staff','support','manreminders','reminders']) {
        if (!perms.includes(p)) perms.push(p);
      }
      await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(perms), u.id]);
    }
  } catch(e) { console.warn('Head Admin permission migration skipped:', e.message); }

  // Sync Manager permissions: ensure support and manreminders are present.
  try {
    const managers = await pool.query(`SELECT id, permissions FROM users WHERE title='Manager' OR roles @> '["Manager"]'::jsonb`);
    for (const u of managers.rows) {
      let perms = Array.isArray(u.permissions) ? u.permissions : [];
      perms = perms.filter(p => !['actions','statistics'].includes(p));
      for (const p of ['support','manreminders','reminders','finance','staff','archived']) {
        if (!perms.includes(p)) perms.push(p);
      }
      await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(perms), u.id]);
    }
  } catch(e) { console.warn('Manager permission migration skipped:', e.message); }

  // Grant 'support' to existing Admin users so they can assign support lessons too.
  try {
    const admins = await pool.query(`SELECT id, permissions FROM users WHERE title='Admin' OR roles @> '["Admin"]'::jsonb`);
    for (const u of admins.rows) {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      if (!perms.includes('support')) {
        await pool.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify([...perms,'support']), u.id]);
      }
    }
  } catch(e) { console.warn('Admin support-permission migration skipped:', e.message); }

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
      AND teacher NOT IN (SELECT first_name || ' ' || last_name FROM users WHERE title='Teacher' OR title='CEO')
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

  // Grant 'vocab' to existing users whose role should have it (new permission)
  await pool.query(`
    UPDATE users SET permissions = permissions || '["vocab"]'::jsonb
    WHERE NOT (permissions @> '["vocab"]'::jsonb)
      AND (role = ANY($1::text[]) OR roles ?| $1::text[])
  `, [['CEO','Head Admin','Manager','Admin','Teacher']]).catch(() => {});

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
async function notifyCEOs(type, title, body, link) {
  const { rows } = await pool.query(`SELECT id FROM users WHERE title='CEO' OR roles @> '["CEO"]'::jsonb`).catch(()=>({rows:[]}));
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
  if (top === 'lead-containers') return write ? 'leads' : null;
  if (top === 'pricing')    return write ? 'finance'    : null;
  if (top === 'levels')     return write ? 'groups'     : null;
  if (top === 'attendance') return write ? 'groups'     : null;
  if (top === 'support')    return write ? 'support'    : null;
  if (top === 'vocab')      return write ? 'vocab'      : null;
  if (top === 'student-codes') return write ? 'students' : null;
  if (top === 'admin')      return 'finance';
  if (top === 'feedback')   return 'feedback'; // CEO-only, reads included — these are students' private complaints/suggestions
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
    if (req.path === '/public/lead-signup' && req.method === 'POST') return next();
    if (req.path.startsWith('/public/lead-test/') && req.method === 'PUT') return next();
    if (req.path.startsWith('/public/vocab/')) return next();
    if (req.path.startsWith('/public/student/')) return next();
    if (req.path.startsWith('/student/')) return next(); // handled by studentAuthMiddleware below
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
    // activity log, reminders/tasks, and their own account (e.g. first-login password change) may be written.
    const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
    const isPureTeacher = userRoles.every(r => isTeacherTitle(r));
    if (isPureTeacher) {
      const seg = p.split('/').filter(Boolean);
      const isGroupUnitWrite = top === 'groups' && seg[2] === 'unit';
      const teacherWriteOk = top === 'attendance' || isGroupUnitWrite || top === 'activity' || top === 'account' || top === 'reminders' || top === 'vocab';
      if (write && !teacherWriteOk) {
        return res.status(403).json({ error: 'Teachers can only mark attendance, update their group\'s unit, grant vocab access, and manage reminders.' });
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

// Student portal auth — fully separate from the staff `users` token/permission system above.
// Student tokens sign 'stu:'+studentId so they can never be confused with a staff token.
function signStudentToken(studentId) { return signToken('stu:' + studentId); }
app.use('/api/student', async (req, res, next) => {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : (req.headers['x-auth-token'] || req.query.token || '');
    const signed = token && verifyToken(token);
    if (!signed || !signed.startsWith('stu:')) return res.status(401).json({ error: 'Not authenticated' });
    const studentId = signed.slice(4);
    const r = await pool.query('SELECT * FROM students WHERE id=$1', [studentId]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Session no longer valid' });
    req.student = r.rows[0];
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
// A support teacher's language ('UZ'/'RU'/'UZ/RU') gates which students can book them:
// UZ-only and RU-only teachers only show up for students in a matching-language group;
// UZ/RU (bilingual) teachers show up for everyone. A student with no group (or a group
// with no lang set) falls back permissively and sees every teacher.
function teacherLangMatches(teacherLang, studentLang) {
  if (!teacherLang || teacherLang === 'UZ/RU') return true;
  if (!studentLang) return true;
  return teacherLang === studentLang;
}
// Support-teacher shifts (separate odd/even), only meaningful for Support Teacher.
// A null start means the teacher does NOT work that day type.
function supportShift(body, title) {
  if (!isSupportTitle(title)) return { oddStart:null, oddEnd:null, evenStart:null, evenEnd:null, lang:null };
  const v = t => /^\d{2}:\d{2}$/.test(t) ? t : null;
  const lang = ['UZ','RU','UZ/RU'].includes(body.supportLang) ? body.supportLang : 'UZ/RU';
  return {
    oddStart:  body.oddStart  ? v(body.oddStart)  : null,
    oddEnd:    body.oddStart  ? (v(body.oddEnd)  || '18:00') : null,
    evenStart: body.evenStart ? v(body.evenStart) : null,
    evenEnd:   body.evenStart ? (v(body.evenEnd) || '18:00') : null,
    lang,
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
      evenStart: u.support_even_start, evenEnd: u.support_even_end,
      supportLang: u.support_lang
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
      'INSERT INTO users(id,first_name,last_name,phone,password,role,title,roles,avatar,permissions,must_change_password,support_odd_start,support_odd_end,support_even_start,support_even_end,support_lang) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,$11,$12,$13,$14,$15)',
      [id, firstName, lastName, phone, password, title, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd, sh.lang]
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
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,password=$4,role=$5,title=$5,roles=$6,avatar=$7,permissions=$8,must_change_password=TRUE,support_odd_start=$9,support_odd_end=$10,support_even_start=$11,support_even_end=$12,support_lang=$13 WHERE id=$14',
        [firstName, lastName, phone, password, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd, sh.lang, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,role=$4,title=$4,roles=$5,avatar=$6,permissions=$7,support_odd_start=$8,support_odd_end=$9,support_even_start=$10,support_even_end=$11,support_lang=$12 WHERE id=$13',
        [firstName, lastName, phone, title, JSON.stringify(roles), avatar, JSON.stringify(perms), sh.oddStart, sh.oddEnd, sh.evenStart, sh.evenEnd, sh.lang, req.params.id]
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
      pool.query("SELECT * FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial') AND is_test IS NOT TRUE ORDER BY created_at DESC"),
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
        freezePeriods: s.freeze_periods || [],
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
    await logStudentHistory(id, actor, req.user?.title||req.user?.role, 'created', { firstName, lastName, phone: phone||null, level: level||null });
    const actorDisplay = req.user ? req.user.last_name+' '+req.user.first_name : 'Someone';
    await notifyRole('staff', 'new_student', 'New student enrolled',
      `${lastName} ${firstName} was added by ${actorDisplay}`, 'students.html', req.user?.id);
    broadcast('students');
    res.json({ ok: true, id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id', async (req, res) => {
  try {
    const { rows: old } = await pool.query('SELECT * FROM students WHERE id=$1', [req.params.id]);
    const prev = old[0];
    if (!prev) return res.status(404).json({ error: 'Not found' });
    // Only overwrite fields the caller actually sent — different edit forms (students list,
    // profile page, group quick-actions) each know about a subset of fields, and a blind
    // full-row overwrite would silently null out whatever fields that form doesn't have.
    const has = k => Object.prototype.hasOwnProperty.call(req.body, k);
    const fieldMap = [
      ['firstName','first_name'], ['lastName','last_name'], ['phone','phone'],
      ['phoneParent','phone_parent'], ['phoneMother','phone_mother'], ['phoneOther','phone_other'],
      ['level','level'], ['status','status'], ['exam','exam'], ['examDate','exam_date'],
      ['notes','notes'], ['school','school'], ['grade','grade'], ['address','address'],
      ['balance_frozen','balance_frozen'], ['frozen_comment','frozen_comment'],
    ];
    const newVals = {};
    for (const [bodyKey, col] of fieldMap) {
      if (!has(bodyKey)) { newVals[col] = prev[col]; continue; }
      const v = req.body[bodyKey];
      newVals[col] = col === 'status' ? (v || 'Active') : col === 'balance_frozen' ? !!v : (v ?? null);
    }
    // Track freeze start/end dates so the attendance table can shade the days a student
    // was frozen once they're reactivated, without touching their actual attendance marks.
    const todayStr = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' })).toISOString().slice(0,10);
    let freezePeriods = Array.isArray(prev.freeze_periods) ? prev.freeze_periods : [];
    if (prev.status !== 'Frozen' && newVals.status === 'Frozen') {
      freezePeriods = [...freezePeriods, { start: todayStr, end: null }];
    } else if (prev.status === 'Frozen' && newVals.status !== 'Frozen') {
      const last = freezePeriods[freezePeriods.length - 1];
      if (last && last.end === null) freezePeriods = [...freezePeriods.slice(0,-1), { ...last, end: todayStr }];
    }
    await pool.query(
      'UPDATE students SET first_name=$1,last_name=$2,phone=$3,phone_parent=$4,phone_mother=$5,phone_other=$6,level=$7,status=$8,exam=$9,exam_date=$10,notes=$11,school=$12,grade=$13,address=$14,balance_frozen=$15,frozen_comment=$16,freeze_periods=$17 WHERE id=$18',
      [newVals.first_name, newVals.last_name, newVals.phone, newVals.phone_parent, newVals.phone_mother, newVals.phone_other,
       newVals.level, newVals.status, newVals.exam, newVals.exam_date, newVals.notes, newVals.school, newVals.grade,
       newVals.address, newVals.balance_frozen, newVals.frozen_comment, JSON.stringify(freezePeriods), req.params.id]
    );
    const actor = req.user ? req.user.first_name+' '+req.user.last_name : 'System';
    const changes = {};
    const keyMap = { first_name:'firstName', last_name:'lastName', phone:'phone', phone_parent:'phoneParent', phone_mother:'phoneMother', phone_other:'phoneOther', level:'level', status:'status', exam:'exam', exam_date:'examDate', notes:'notes', school:'school', grade:'grade', address:'address', balance_frozen:'balanceFrozen', frozen_comment:'frozenComment' };
    for (const [col, key] of Object.entries(keyMap)) {
      const oldVal = prev[col] ?? null;
      const newVal = newVals[col] ?? null;
      if (String(oldVal||'') !== String(newVal||'')) changes[key] = { from: oldVal, to: newVal };
    }
    if (Object.keys(changes).length) await logStudentHistory(req.params.id, actor, req.user?.title||req.user?.role, 'profile_updated', changes);
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
    await logStudentHistory(sid, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'archived', { reason: reason||null, comment: comment||null });
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
      name: s.last_name + ' ' + s.first_name,
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
    await logStudentHistory(req.params.id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'restored', {});
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
      const totalLessons = countLessons(year, month, lessonDays, 1);
      const remaining    = Math.max(0, countLessons(year, month, lessonDays, today));
      const amount       = totalLessons > 0
        ? Math.round(monthlyPrice * remaining / totalLessons / 1000) * 1000
        : monthlyPrice;

      // Record invoice + update balance
      const invId  = 'inv-' + Date.now();
      const invNum = 'INV-' + Date.now().toString().slice(-6);
      const mStr   = `${year}-${String(month + 1).padStart(2, '0')}`;
      await pool.query(
        `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type)
         VALUES($1,$2,$3,$4,$5,$6,$7,'Pending','Auto')`,
        [invId, invNum, studentId, groupId, mStr,
         `Activation – ${remaining} of ${totalLessons} lessons (${g.name})`, amount]
      );

      const stuRes = await pool.query('SELECT balance FROM students WHERE id=$1', [studentId]);
      const newBal = Number(stuRes.rows[0]?.balance || 0) - amount;
      await pool.query('UPDATE students SET balance=$1 WHERE id=$2', [newBal, studentId]);

      await logStudentHistory(studentId, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'activated', { groupId, groupName: g.name, charge: amount });
      broadcast('students');
      return res.json({ ok: true, amount, remaining });
    }

    await logStudentHistory(studentId, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'activated', { groupId, charge: 0 });
    broadcast('students');
    res.json({ ok: true, amount: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// CEO-only: directly set student balance
app.patch('/api/students/:id/balance', async (req, res) => {
  try {
    if (req.user?.role !== 'CEO') return res.status(403).json({ error: 'CEO only' });
    const { balance, reason } = req.body;
    const val = Number(balance);
    if (isNaN(val)) return res.status(400).json({ error: 'Invalid balance' });
    const prevRes = await pool.query('SELECT balance FROM students WHERE id=$1', [req.params.id]);
    const oldBal = Number(prevRes.rows[0]?.balance || 0);
    await pool.query('UPDATE students SET balance=$1 WHERE id=$2', [val, req.params.id]);
    await logStudentHistory(req.params.id, req.user.first_name+' '+req.user.last_name, req.user.role, 'balance_adjusted', { from: oldBal, to: val, reason: reason||null });
    broadcast('students');
    broadcast('finance');
    res.json({ ok: true, balance: val });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Adjust balance (add payment)
app.post('/api/students/:id/payment', async (req, res) => {
  try {
    const { amount, paymentType, groupId, desc, notes, creator } = req.body;
    const num = Number(amount);
    const isSubtract = paymentType === 'Subtract' || num < 0;
    const finalType = isSubtract ? 'Subtract' : (paymentType || 'Cash');
    const finalTotal = isSubtract ? -Math.abs(num) : Math.abs(num);
    // Subtract: deducts balance immediately (like Auto). Payment: credits balance.
    await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [finalTotal, req.params.id]);
    // Create invoice
    const id = 'inv-' + Date.now();
    const number = 'INV-' + Date.now().toString().slice(-6);
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const month = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0');
    // Subtract invoices are Pending (deducted on creation); payments are Paid.
    const invoiceStatus = isSubtract ? 'Pending' : 'Paid';
    await pool.query(
      `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type,notes,creator)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, number, req.params.id, groupId||null, month, desc||'Payment', finalTotal, invoiceStatus, finalType, notes||null, creator||null]
    );
    const balRes = await pool.query('SELECT balance FROM students WHERE id=$1', [req.params.id]);
    const newBalance = Number(balRes.rows[0]?.balance || 0);
    const { type: payType, desc: payDesc } = req.body;
    await logStudentHistory(req.params.id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'payment_added', { amount: num, type: payType, description: payDesc||null });
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
    await logStudentHistory(req.params.id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'comment_added', { text: req.body.text });
    broadcast('students');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/students/comments/:commentId', async (req, res) => {
  try {
    const { rows: commentRows } = await pool.query('SELECT student_id, text FROM student_comments WHERE id=$1', [req.params.commentId]);
    const comment = commentRows[0];
    await pool.query('DELETE FROM student_comments WHERE id=$1', [req.params.commentId]);
    if (comment) await logStudentHistory(comment.student_id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'comment_deleted', { text: comment.text });
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
    const { rows } = await pool.query("SELECT id,first_name,last_name,phone,created_at FROM users WHERE title='Teacher' OR title='CEO' ORDER BY first_name");
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
    // Deactivate removed students. Balance is a single running total with no per-invoice
    // payment tracking, so there's no safe way to auto-reverse a pending Auto charge here —
    // it may already have been settled by a later payment, and reversing it would silently
    // wipe out real debt (or double-credit a charge that was already paid). Leave balance and
    // invoices untouched; staff can edit/delete a specific invoice manually if it was a mistake.
    if (removed.length) {
      const allGroups = await pool.query('SELECT student_ids FROM groups WHERE id!=$1', [req.params.id]);
      const stillEnrolled = new Set(allGroups.rows.flatMap(g => g.student_ids || []));
      for (const sid of removed) {
        if (!stillEnrolled.has(sid)) {
          await pool.query("UPDATE students SET status='Inactive' WHERE id=$1", [sid]);
        }
      }
    }
    const actorName = req.user ? req.user.first_name+' '+req.user.last_name : 'System';
    const actorRole = req.user?.title||req.user?.role;
    for (const sid of added) await logStudentHistory(sid, actorName, actorRole, 'group_added', { groupId: req.params.id, groupName: groupName });
    for (const sid of removed) await logStudentHistory(sid, actorName, actorRole, 'group_removed', { groupId: req.params.id, groupName: groupName });
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
    // Sync balance: compute what the invoice contributed before vs after, apply the delta
    if (prev && (prev.student_id || studentId)) {
      const sid = prev.student_id || studentId;
      const balanceContribution = (invTotal, invStatus, invPayType) => {
        const t = Number(invTotal) || 0;
        if (invPayType === 'Auto' && invStatus !== 'Cancelled') return -t;     // Auto: positive total, deducts balance
        if (invPayType === 'Subtract' && invStatus !== 'Cancelled') return t;  // Subtract: negative total, deducts balance
        if (invPayType !== 'Auto' && invPayType !== 'Subtract' && invStatus === 'Paid') return t; // payment credits balance
        return 0;
      };
      const oldContrib = balanceContribution(prev.total, prev.status, prev.payment_type);
      const newContrib = balanceContribution(total, status||'Pending', paymentType||'Cash');
      const delta = newContrib - oldContrib;
      if (delta !== 0) {
        await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [delta, sid]);
      }
    }
    if (prev?.student_id) {
      await logStudentHistory(prev.student_id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'payment_edited', { invoiceId: req.params.id, total: Number(total)||0, description: desc||null });
    }
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/invoices/:id/status', async (req, res) => {
  try {
    const { status, paymentType } = req.body;
    const prevRes = await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id]);
    const inv = prevRes.rows[0];
    await pool.query('UPDATE invoices SET status=$1,payment_type=$2 WHERE id=$3', [status, paymentType||'Cash', req.params.id]);
    if (inv && inv.student_id) {
      const pt = inv.payment_type;
      const isAutoCharge = pt === 'Auto' || (inv.description||'').toLowerCase().startsWith('activation');
      const isSubtract = pt === 'Subtract';
      if (isAutoCharge || isSubtract) {
        // These types apply balance on creation; restore on Cancelled.
        // Auto: positive total → created deducted balance (balance-=total), cancel restores (balance+=total)
        // Subtract: negative total → created deducted balance (balance+=total), cancel restores (balance-=total)
        const wasCancelled = inv.status === 'Cancelled';
        const nowCancelled = status === 'Cancelled';
        const restoreOp = isSubtract ? 'balance-$1' : 'balance+$1';
        const reapplyOp = isSubtract ? 'balance+$1' : 'balance-$1';
        if (!wasCancelled && nowCancelled) {
          await pool.query(`UPDATE students SET ${restoreOp} WHERE id=$2`, [Math.abs(Number(inv.total)), inv.student_id]);
        } else if (wasCancelled && !nowCancelled) {
          await pool.query(`UPDATE students SET ${reapplyOp} WHERE id=$2`, [Math.abs(Number(inv.total)), inv.student_id]);
        }
      } else {
        // Manual invoice: balance credited only when Paid
        const wasPaid = inv.status === 'Paid';
        const nowPaid = status === 'Paid';
        if (!wasPaid && nowPaid) {
          await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [Number(inv.total), inv.student_id]);
        } else if (wasPaid && !nowPaid) {
          await pool.query('UPDATE students SET balance=balance-$1 WHERE id=$2', [Number(inv.total), inv.student_id]);
        }
      }
    }
    broadcast('finance');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/invoices/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM invoices WHERE id=$1', [req.params.id]);
    const inv = rows[0];
    if (inv && inv.student_id) {
      const pt = inv.payment_type;
      const isAutoCharge = pt === 'Auto';
      const isSubtract = pt === 'Subtract';
      if (isAutoCharge && inv.status !== 'Cancelled') {
        // Auto charge deducted balance when created (balance-=total) — restore it
        await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [Number(inv.total), inv.student_id]);
      } else if (isSubtract && inv.status !== 'Cancelled') {
        // Subtract deducted balance when created (balance+=negative_total) — restore it
        await pool.query('UPDATE students SET balance=balance-$1 WHERE id=$2', [Number(inv.total), inv.student_id]);
      } else if (!isAutoCharge && !isSubtract && inv.status === 'Paid') {
        // Manual Paid invoice credited balance — reverse it
        await pool.query('UPDATE students SET balance=balance-$1 WHERE id=$2', [Number(inv.total), inv.student_id]);
      }
      // Pending non-charge: balance was never touched, no adjustment needed
      // Cancelled: balance was already restored when cancelled, no adjustment needed
    }
    if (inv?.student_id) {
      await logStudentHistory(inv.student_id, req.user ? req.user.first_name+' '+req.user.last_name : 'System', req.user?.title||req.user?.role, 'payment_deleted', { invoiceId: req.params.id, total: Number(inv.total)||0, description: inv.description||null });
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
// Students may only self-book for today or up to 2 days ahead (admins booking on the
// staff side are not subject to this — see POST /api/support).
function studentMaxBookingDate(nowTz) {
  const d = new Date(nowTz); d.setDate(d.getDate() + 2);
  return d.toISOString().split('T')[0];
}

// Shared validation + insert for booking a support session — used by both the admin
// booking route (POST /api/support) and the student self-booking route
// (POST /api/student/support/book). Throws { status, message } on any rule violation.
async function createSupportSession({ id, date, time, duration, teacher, studentId, theme }) {
  if (!date || !time || !teacher || !studentId) throw { status: 400, message: 'Date, time, teacher and student are required.' };
  if (!theme || !theme.trim()) throw { status: 400, message: 'Theme is required.' };
  // Block past times
  const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
  const todayISO = nowTz.toISOString().split('T')[0];
  if (date < todayISO) throw { status: 409, message: 'Cannot book sessions in the past.' };
  if (date === todayISO) {
    const [hh, mm] = time.split(':').map(Number);
    const slotMin = hh * 60 + mm;
    const nowMin = nowTz.getHours() * 60 + nowTz.getMinutes();
    if (slotMin <= nowMin) throw { status: 409, message: 'This time slot has already passed.' };
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
    if (!shiftStart) throw { status: 409, message: 'This teacher does not work on this day.' };
    if (start < toMin(shiftStart) || end > toMin(shiftEnd)) throw { status: 409, message: "Outside this teacher's working hours." };
  }
  // Block fined students
  const fineCheck = await pool.query('SELECT 1 FROM support_fines WHERE student_id=$1 AND blocked_until > NOW() LIMIT 1', [studentId]);
  if (fineCheck.rows.length) throw { status: 409, message: 'This student is currently fined and cannot book support sessions.' };

  const { rows } = await pool.query('SELECT * FROM support_sessions WHERE date=$1', [date]);
  const overlap = rows.filter(s => { const st=toMin(s.time), en=st+Number(s.duration||30); return start < en && st < end; });
  if (overlap.length >= 2) throw { status: 409, message: 'Both support slots are already taken at this time.' };
  if (overlap.some(s => s.teacher === teacher)) throw { status: 409, message: 'This teacher already has a session at this time.' };
  await pool.query(
    'INSERT INTO support_sessions(id,date,time,duration,teacher,student_id,theme) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [id, date, time, dur, teacher, studentId, theme.trim()]
  );
  broadcast('support');
}

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
    res.json(rows.map(s => ({ id:s.id, date:s.date, time:s.time, duration:s.duration, teacher:s.teacher, studentId:s.student_id, theme:s.theme, attended:s.attended })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/support', async (req, res) => {
  try {
    await createSupportSession(req.body);
    res.json({ ok: true });
  } catch(e) {
    if (e && e.status) return res.status(e.status).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/support/:id', async (req, res) => {
  const adminRoles = ['CEO','Head Admin','Manager','Admin'];
  const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
  if (!userRoles.some(r => adminRoles.includes(r)))
    return res.status(403).json({ error: 'Only administration can delete support sessions.' });
  try { await pool.query('DELETE FROM support_sessions WHERE id=$1', [req.params.id]); broadcast('support'); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/support-fines/:id', async (req, res) => {
  const allowedRoles = ['CEO','Head Admin','Manager'];
  const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
  if (!userRoles.some(r => allowedRoles.includes(r)))
    return res.status(403).json({ error: 'Only CEO, Head Admin, or Manager can remove fines.' });
  try { await pool.query('DELETE FROM support_fines WHERE id=$1', [req.params.id]); broadcast('support'); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Mark attendance + optional theme for a session
app.put('/api/support/:id/attend', async (req, res) => {
  try {
    const { attended, theme } = req.body;
    // Theme is set once at booking; only overwrite it here if a real value was sent
    // (marking attendance must not wipe the theme recorded when the session was created).
    await pool.query('UPDATE support_sessions SET attended=$1, theme=COALESCE($2, theme) WHERE id=$3', [attended, theme||null, req.params.id]);
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
    const monthEndDate = new Date(tzNow.getFullYear(), tzNow.getMonth()+1, 1);
    const monthEnd = `${monthEndDate.getFullYear()}-${String(monthEndDate.getMonth()+1).padStart(2,'0')}-01`;

    const [stuR, fineR, todayR, monthR, shiftR, historyR] = await Promise.all([
      pool.query('SELECT id, first_name, last_name FROM students WHERE archived IS NOT TRUE'),
      pool.query('SELECT id, student_id, blocked_until FROM support_fines WHERE blocked_until > NOW()'),
      isSupport
        ? pool.query(`SELECT * FROM support_sessions WHERE teacher=$1 AND date=$2 ORDER BY time`, [myName, today])
        : pool.query(`SELECT * FROM support_sessions WHERE date=$1 ORDER BY teacher, time`, [today]),
      isSupport
        ? pool.query(`SELECT teacher, duration, attended FROM support_sessions WHERE teacher=$1 AND date>=$2 AND date<$3`, [myName, monthStart, monthEnd])
        : pool.query(`SELECT teacher, duration, attended FROM support_sessions WHERE date>=$1 AND date<$2`, [monthStart, monthEnd]),
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
        studentName: stu ? stu.last_name + ' ' + stu.first_name : '?',
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
        studentId: s.student_id,
        studentName: stu ? stu.last_name + ' ' + stu.first_name : '?',
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
          id: f.id,
          name: stu ? stu.last_name+' '+stu.first_name : '?',
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

app.get('/api/students/:id/history', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM student_history WHERE student_id=$1 ORDER BY created_at DESC LIMIT 200`,
      [req.params.id]
    );
    res.json(rows.map(r => ({
      id: r.id, action: r.action, actor: r.actor, actorRole: r.actor_role,
      details: r.details || {}, createdAt: r.created_at
    })));
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

/* ══════════════════════════════════════
   VOCABULARY TEST
   - vocab_units: admin-managed word banks per theme ("unit"). Each word carries all 3
     languages (en/ru/uz, each with optional alternate accepted answers).
   - vocab_access: a single-use code an admin/teacher grants a student, covering one or
     more units and a chosen language pair (RU-ENG or ENG-UZ). The student enters the
     code on the standalone public test page (not linked in app nav yet).
   - vocab_attempts: completed results, for admin review.
══════════════════════════════════════ */
function genVocabId(prefix) { return prefix + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function genVocabCode() { return String(Math.floor(100000 + Math.random() * 900000)); } // 6 digits

// Pass rule: a max number of wrong answers, scaled to how many questions were actually
// asked (post-sampling), not the unit's raw word count. Single source of truth — the
// group page's Vocabulary tab reads the stored `passed` value rather than recomputing.
function maxMistakesAllowed(total) {
  if (total <= 6) return 0;
  if (total <= 12) return 2;
  if (total <= 20) return 3;
  if (total <= 50) return 4;
  return 5;
}
function vocabPassed(score, total) { return total > 0 && (total - score) <= maxMistakesAllowed(total); }

// Shared by the admin-graded test flow (/api/public/vocab/test/*) and the student
// self-practice flow (/api/student/vocab/practice/*) — builds a shuffled, mixed-direction
// question set (with correct answers embedded) from a pool of trilingual words.
function buildQuestionSet(allWords, languagePair) {
  const backKey = languagePair === 'ENG-UZ' ? 'uz' : 'ru';
  const backAltKey = languagePair === 'ENG-UZ' ? 'uzAlt' : 'ruAlt';
  const allEnglish = [...new Set(allWords.map(w => w.en))];
  // Sample size: 20 or fewer words -> ask all of them. More than 50 -> cap at 80% of
  // 50 (= 40), even if the unit has far more words. In between, 80% of the actual count.
  const n = allWords.length;
  const sampleSize = n <= 20 ? n : (n > 50 ? 40 : Math.ceil(n * 0.8));
  const shuffledWords = [...allWords];
  for (let i = shuffledWords.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffledWords[i], shuffledWords[j]] = [shuffledWords[j], shuffledWords[i]];
  }
  const words = shuffledWords.slice(0, sampleSize);
  const questionSet = words.map(w => {
    const isPhrase = w.en.trim().includes(' ');
    let options = null;
    if (isPhrase) {
      // Multiple choice for multi-word answers — typing a whole phrase is slow.
      const distractorPool = allEnglish.filter(e => e !== w.en);
      for (let i = distractorPool.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [distractorPool[i], distractorPool[j]] = [distractorPool[j], distractorPool[i]];
      }
      options = [w.en, ...distractorPool.slice(0, 3)];
      for (let i = options.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [options[i], options[j]] = [options[j], options[i]];
      }
    }
    return { prompt: w[backKey], promptAlt: w[backAltKey] || [], en: w.en, enAlt: w.enAlt || [], options };
  });
  // shuffle order
  for (let i = questionSet.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [questionSet[i], questionSet[j]] = [questionSet[j], questionSet[i]];
  }
  return questionSet;
}

// Scores a submitted answer set against a stored question set. Returns { score, total, passed, details }.
function scoreQuestionSet(questionSet, submittedAnswers) {
  const norm = s => String(s || '').trim().toLowerCase();
  const givenByQid = new Map((Array.isArray(submittedAnswers) ? submittedAnswers : []).map(a => [a.qid, a.given]));
  let score = 0;
  const details = questionSet.map((q, qid) => {
    const accepted = [q.en, ...(q.enAlt || [])].map(norm);
    const given = givenByQid.get(qid);
    const correct = accepted.includes(norm(given));
    if (correct) score++;
    return { qid, prompt: q.prompt, given: given || '', expected: q.en, correct };
  });
  const total = questionSet.length;
  return { score, total, passed: vocabPassed(score, total), details };
}

function cleanWordField(v) {
  return String(v || '').trim().slice(0, 150);
}
function cleanWordAlts(v) {
  return Array.isArray(v) ? v.map(s => String(s).trim().slice(0, 150)).filter(Boolean) : [];
}
function cleanWords(words) {
  return Array.isArray(words) ? words
    .map(w => ({
      en: cleanWordField(w.en), enAlt: cleanWordAlts(w.enAlt),
      ru: cleanWordField(w.ru), ruAlt: cleanWordAlts(w.ruAlt),
      uz: cleanWordField(w.uz), uzAlt: cleanWordAlts(w.uzAlt),
    }))
    .filter(w => w.en && w.ru && w.uz) : [];
}

app.get('/api/vocab/units', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM vocab_units ORDER BY created_at DESC');
    res.json(rows.map(u => ({
      id: u.id, name: u.name, level: u.level,
      words: u.words || [], wordCount: (u.words || []).length, createdAt: u.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vocab/units', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 120);
    const level = String(req.body.level || '').trim().slice(0, 40);
    const words = cleanWords(req.body.words);
    if (!name) return res.status(400).json({ error: 'Unit name is required.' });
    if (!level) return res.status(400).json({ error: 'Level is required.' });
    if (!words.length) return res.status(400).json({ error: 'At least one word (with English, Russian and Uzbek) is required.' });
    const id = genVocabId('vunit');
    await pool.query(
      `INSERT INTO vocab_units(id, name, level, words) VALUES($1,$2,$3,$4)`,
      [id, name, level, JSON.stringify(words)]
    );
    broadcast('vocab');
    res.json({ ok: true, id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/vocab/units/:id', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 120);
    const level = String(req.body.level || '').trim().slice(0, 40);
    const words = cleanWords(req.body.words);
    if (!name) return res.status(400).json({ error: 'Unit name is required.' });
    if (!level) return res.status(400).json({ error: 'Level is required.' });
    if (!words.length) return res.status(400).json({ error: 'At least one word (with English, Russian and Uzbek) is required.' });
    const { rowCount } = await pool.query(
      `UPDATE vocab_units SET name=$1, level=$2, words=$3 WHERE id=$4`,
      [name, level, JSON.stringify(words), req.params.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Unit not found.' });
    broadcast('vocab');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/vocab/units/:id', async (req, res) => {
  try {
    // Pending (unused) access grants that reference only this unit become unusable — drop them.
    // Grants that also include other units keep those units, just lose this one.
    await pool.query(
      `DELETE FROM vocab_access WHERE used IS NOT TRUE AND unit_ids @> to_jsonb($1::text) AND jsonb_array_length(unit_ids) = 1`,
      [req.params.id]
    );
    await pool.query(
      `UPDATE vocab_access SET unit_ids = unit_ids - $1 WHERE used IS NOT TRUE AND unit_ids @> to_jsonb($1::text)`,
      [req.params.id]
    );
    await pool.query('DELETE FROM vocab_units WHERE id=$1', [req.params.id]);
    broadcast('vocab');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/vocab/access', async (req, res) => {
  try {
    const [accessR, unitsR] = await Promise.all([
      pool.query(`
        SELECT a.*, s.first_name AS s_first, s.last_name AS s_last
        FROM vocab_access a
        LEFT JOIN students s ON s.id = a.student_id
        ORDER BY a.created_at DESC LIMIT 300
      `),
      pool.query('SELECT id, name FROM vocab_units'),
    ]);
    const unitNames = new Map(unitsR.rows.map(u => [u.id, u.name]));
    res.json(accessR.rows.map(a => ({
      id: a.id, code: a.code, studentId: a.student_id,
      studentName: a.s_first ? `${a.s_last} ${a.s_first}` : '(deleted student)',
      unitIds: a.unit_ids || [],
      unitNames: (a.unit_ids || []).map(id => unitNames.get(id) || '(deleted unit)'),
      languagePair: a.language_pair,
      grantedBy: a.granted_by, used: a.used, usedAt: a.used_at, createdAt: a.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vocab/access', async (req, res) => {
  try {
    const { studentId } = req.body;
    const unitIds = Array.isArray(req.body.unitIds) ? [...new Set(req.body.unitIds.filter(Boolean))] : [];
    if (!studentId || !unitIds.length) return res.status(400).json({ error: 'studentId and at least one unit are required.' });
    const [stu, units, groupR] = await Promise.all([
      pool.query('SELECT id FROM students WHERE id=$1', [studentId]),
      pool.query('SELECT id, level FROM vocab_units WHERE id = ANY($1::text[])', [unitIds]),
      // The group's instruction language decides the pair: a UZ-medium group tests
      // ENG-UZ, an RU-medium group tests RU-ENG. Ungrouped/unknown students default RU-ENG.
      // The group's level restricts which units may be picked at all.
      pool.query(`SELECT lang, level FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [studentId]),
    ]);
    if (!stu.rows[0]) return res.status(404).json({ error: 'Student not found.' });
    if (units.rows.length !== unitIds.length) return res.status(404).json({ error: 'One or more units were not found.' });
    const studentLevel = groupR.rows[0]?.level || null;
    if (studentLevel && units.rows.some(u => u.level !== studentLevel)) {
      return res.status(400).json({ error: `This student's group is ${studentLevel} — pick units at that level.` });
    }
    const languagePair = groupR.rows[0]?.lang === 'UZ' ? 'ENG-UZ' : 'RU-ENG';
    const id = genVocabId('vacc');
    let code;
    for (let i = 0; i < 10; i++) {
      code = genVocabCode();
      const clash = await pool.query('SELECT 1 FROM vocab_access WHERE code=$1', [code]);
      if (!clash.rows[0]) break;
    }
    const actor = req.user ? `${req.user.last_name} ${req.user.first_name}` : 'Someone';
    await pool.query(
      `INSERT INTO vocab_access(id, code, student_id, unit_ids, language_pair, granted_by) VALUES($1,$2,$3,$4,$5,$6)`,
      [id, code, studentId, JSON.stringify(unitIds), languagePair, actor]
    );
    broadcast('vocab');
    res.json({ ok: true, id, code, languagePair });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/vocab/access/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM vocab_access WHERE id=$1 AND used IS NOT TRUE', [req.params.id]);
    broadcast('vocab');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/vocab/attempts', async (req, res) => {
  try {
    const [attemptsR, unitsR] = await Promise.all([
      pool.query(`
        SELECT t.*, s.first_name AS s_first, s.last_name AS s_last
        FROM vocab_attempts t
        LEFT JOIN students s ON s.id = t.student_id
        ORDER BY t.completed_at DESC LIMIT 300
      `),
      pool.query('SELECT id, name FROM vocab_units'),
    ]);
    const unitNames = new Map(unitsR.rows.map(u => [u.id, u.name]));
    res.json(attemptsR.rows.map(t => ({
      id: t.id, studentId: t.student_id,
      studentName: t.s_first ? `${t.s_last} ${t.s_first}` : '(deleted student)',
      unitIds: t.unit_ids || [],
      unitNames: (t.unit_ids || []).map(id => unitNames.get(id) || '(deleted unit)'),
      // Older attempts recorded before the `passed` column existed: fall back to computing it.
      score: t.score, total: t.total, passed: t.passed !== null ? t.passed : vocabPassed(t.score, t.total),
      completedAt: t.completed_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════
   STUDENT PORTAL — registration codes (admin side)
   Same one-time-code pattern as vocab_access: an admin picks an existing student and
   generates a random code; the student redeems it on student-register.html to set up
   their own phone+password login (see student_logins / student_portal_codes tables).
══════════════════════════════════════ */
function genStudentCode() {
  // 8 chars, uppercase letters+digits, no ambiguous 0/O/1/I — easy to read out loud.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += alphabet[Math.floor(Math.random() * alphabet.length)];
  return code;
}

app.get('/api/student-codes', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, s.first_name AS s_first, s.last_name AS s_last
      FROM student_portal_codes c
      LEFT JOIN students s ON s.id = c.student_id
      ORDER BY c.created_at DESC LIMIT 300
    `);
    res.json(rows.map(c => ({
      id: c.id, code: c.code, studentId: c.student_id,
      studentName: c.s_first ? `${c.s_last} ${c.s_first}` : '(deleted student)',
      grantedBy: c.granted_by, used: c.used, usedAt: c.used_at, createdAt: c.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/student-codes', async (req, res) => {
  try {
    const { studentId } = req.body;
    if (!studentId) return res.status(400).json({ error: 'studentId is required.' });
    const stu = await pool.query('SELECT id FROM students WHERE id=$1', [studentId]);
    if (!stu.rows[0]) return res.status(404).json({ error: 'Student not found.' });
    const id = genVocabId('spc');
    let code;
    for (let i = 0; i < 10; i++) {
      code = genStudentCode();
      const clash = await pool.query('SELECT 1 FROM student_portal_codes WHERE code=$1', [code]);
      if (!clash.rows[0]) break;
    }
    const actor = req.user ? `${req.user.last_name} ${req.user.first_name}` : 'Someone';
    await pool.query(
      `INSERT INTO student_portal_codes(id, code, student_id, granted_by) VALUES($1,$2,$3,$4)`,
      [id, code, studentId, actor]
    );
    res.json({ ok: true, id, code });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/student-codes/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM student_portal_codes WHERE id=$1 AND used IS NOT TRUE', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════
   STUDENT PORTAL — public (unauthenticated) registration + login
══════════════════════════════════════ */
app.post('/api/public/student/redeem', async (req, res) => {
  try {
    const code = String(req.body.code || '').trim().toUpperCase();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!code || !username || !password) return res.status(400).json({ error: 'Code, username and password are required.' });
    if (!/^[a-z0-9_.]{3,24}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-24 characters: letters, numbers, "_" or "." only.' });
    if (username === 'test') return res.status(400).json({ error: 'That username is reserved — pick another.' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    const { rows } = await pool.query('SELECT * FROM student_portal_codes WHERE code=$1', [code]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Invalid code.' });
    if (row.used) return res.status(410).json({ error: 'This code has already been used. Ask your admin for a new one.' });
    const stu = await pool.query('SELECT id, first_name, last_name FROM students WHERE id=$1', [row.student_id]);
    if (!stu.rows[0]) return res.status(404).json({ error: 'The student record for this code no longer exists.' });
    const taken = await pool.query('SELECT 1 FROM student_logins WHERE username=$1 AND student_id<>$2', [username, row.student_id]);
    if (taken.rows.length) return res.status(409).json({ error: 'That username is already taken — pick another.' });
    await pool.query(
      `INSERT INTO student_logins(student_id, username, password) VALUES($1,$2,$3)
       ON CONFLICT (student_id) DO UPDATE SET username=$2, password=$3`,
      [row.student_id, username, password]
    );
    await pool.query('UPDATE student_portal_codes SET used=TRUE, used_at=NOW() WHERE id=$1', [row.id]);
    res.json({ ok: true, token: signStudentToken(row.student_id), name: `${stu.rows[0].first_name} ${stu.rows[0].last_name}` });
  } catch(e) {
    if (e && e.code === '23505') return res.status(409).json({ error: 'That username is already taken — pick another.' });
    res.status(500).json({ error: e.message });
  }
});

// Provisions (or reuses) the single hidden test student account. Marked is_test=TRUE so
// it's filtered out of every admin roster/dashboard/statistics query — it must never
// look like a real enrolled student.
async function ensureHiddenTestStudent() {
  const id = 'dev_test_student';
  await pool.query(
    `INSERT INTO students(id, first_name, last_name, phone, level, status, balance, is_test)
     VALUES($1,'Test','Student','90 000 00 00','Elementary','Active',0,TRUE)
     ON CONFLICT (id) DO UPDATE SET first_name='Test', last_name='Student', is_test=TRUE`,
    [id]
  );
  return id;
}

app.post('/api/public/student/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    // Hidden testing backdoor: typing "test" as the username logs straight into a
    // reusable, hidden test-only student account — no real password check, works from
    // anywhere (not just localhost, unlike /dev-login). Not linked from any UI; the
    // account is excluded from all admin-facing student counts via is_test.
    if (username === 'test') {
      const id = await ensureHiddenTestStudent();
      return res.json({ ok: true, token: signStudentToken(id), name: 'Test Student' });
    }
    const { rows } = await pool.query(
      `SELECT l.student_id, s.first_name, s.last_name FROM student_logins l
       JOIN students s ON s.id = l.student_id
       WHERE l.username=$1 AND l.password=$2`,
      [username, password]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid username or password.' });
    const r = rows[0];
    res.json({ ok: true, token: signStudentToken(r.student_id), name: `${r.first_name} ${r.last_name}` });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Dev-only shortcut: skips the code/username/password flow entirely and logs straight
// into a reusable throwaway student record. Gated on the request host being localhost —
// refuses on any real domain, so this can never be used against the live site even
// though it shares the same database as production.
app.post('/api/public/student/dev-login', async (req, res) => {
  try {
    const host = String(req.hostname || '');
    if (host !== 'localhost' && host !== '127.0.0.1') {
      return res.status(403).json({ error: 'Dev login is only available on localhost.' });
    }
    const id = await ensureHiddenTestStudent();
    res.json({ ok: true, token: signStudentToken(id), name: 'Test Student' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ══════════════════════════════════════
   STUDENT PORTAL — authenticated student-facing routes
   Everything below reads/writes only req.student.id (set by the studentAuthMiddleware
   above) — a student can never pass a studentId to act on someone else's data.
══════════════════════════════════════ */
app.get('/api/student/me', async (req, res) => {
  try {
    const s = req.student;
    const [enr, groupsR, attR] = await Promise.all([
      pool.query('SELECT 1 FROM groups WHERE student_ids @> $1::jsonb LIMIT 1', [JSON.stringify([s.id])]),
      pool.query(`SELECT * FROM groups WHERE student_ids @> $1::jsonb ORDER BY created_at DESC`, [JSON.stringify([s.id])]),
      pool.query(
        `SELECT a.date, a.status, a.group_id, g.name AS group_name FROM attendance a
         LEFT JOIN groups g ON g.id = a.group_id WHERE a.student_id=$1 ORDER BY a.date DESC LIMIT 120`,
        [s.id]
      ),
    ]);
    res.json({
      id: s.id, firstName: s.first_name, lastName: s.last_name,
      phone: s.phone, phoneParent: s.phone_parent, phoneMother: s.phone_mother, phoneOther: s.phone_other,
      level: s.level, status: enr.rows.length ? (s.status === 'Frozen' ? 'Frozen' : 'Active') : 'Inactive',
      balance: Number(s.balance || 0), exam: s.exam, examDate: s.exam_date,
      school: s.school, grade: s.grade, address: s.address,
      groups: groupsR.rows.map(g => ({
        id: g.id, name: g.name, teacher: g.teacher, room: g.room, level: g.level,
        schedType: g.sched_type, time: g.time, duration: g.duration, startDate: g.start_date,
        currentUnit: g.current_unit,
      })),
      attendance: attR.rows.map(r => ({ date: r.date, status: r.status, groupId: r.group_id, groupName: r.group_name })),
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/student/account/change-password', async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '');
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required.' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'New password must be at least 4 characters.' });
    const { rows } = await pool.query('SELECT password FROM student_logins WHERE student_id=$1', [req.student.id]);
    if (!rows[0] || rows[0].password !== currentPassword) return res.status(401).json({ error: 'Current password is incorrect.' });
    await pool.query('UPDATE student_logins SET password=$1 WHERE student_id=$2', [newPassword, req.student.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Same odd/even/daily/custom → day-of-week mapping as the groups dashboard's lesson
// counter, just standalone here (that one is defined inline inside its own route).
function studentGroupLessonDays(schedType, customDays) {
  if (schedType === 'odd')   return [1, 3, 5];
  if (schedType === 'even')  return [2, 4, 6];
  if (schedType === 'daily') return [1, 2, 3, 4, 5];
  if (schedType === 'custom' && customDays?.length) {
    const map = { Mon:1, Tue:2, Wed:3, Thu:4, Fri:5, Sat:6, Sun:0 };
    return customDays.map(d => map[d]).filter(d => d !== undefined);
  }
  return [1, 3, 5];
}
// Next occurrence of a group's lesson time, strictly after `now` (Tashkent-local Date).
function nextClassOccurrence(group, now) {
  const days = studentGroupLessonDays(group.sched_type, group.custom_days);
  if (!days.length || !group.time) return null;
  const [hh, mm] = String(group.time).split(':').map(Number);
  for (let i = 0; i < 14; i++) {
    const d = new Date(now); d.setDate(d.getDate() + i); d.setHours(hh || 0, mm || 0, 0, 0);
    if (days.includes(d.getDay()) && d > now) return d;
  }
  return null;
}
// Consecutive-day vocab practice streak ending today or yesterday (a day not yet
// practiced today doesn't break the streak until the day is over).
async function computeStreak(studentId, nowTz) {
  const { rows } = await pool.query(
    `SELECT DISTINCT to_char((completed_at AT TIME ZONE 'Asia/Tashkent')::date, 'YYYY-MM-DD') AS d
     FROM vocab_practice_attempts WHERE student_id=$1`,
    [studentId]
  );
  const daySet = new Set(rows.map(r => r.d));
  const isoOf = d => d.toISOString().split('T')[0];
  let cursor = new Date(nowTz);
  if (!daySet.has(isoOf(cursor))) {
    cursor.setDate(cursor.getDate() - 1);
    if (!daySet.has(isoOf(cursor))) return 0;
  }
  let streak = 0;
  while (daySet.has(isoOf(cursor))) { streak++; cursor.setDate(cursor.getDate() - 1); }
  return streak;
}

// Home screen extras: learning streak + "what's next" (next class, next booked support
// session, any vocabulary test an admin has granted but the student hasn't taken yet).
app.get('/api/student/home', async (req, res) => {
  try {
    const studentId = req.student.id;
    const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const todayISO = nowTz.toISOString().split('T')[0];

    const [groupsR, supportR, pendingR, streak, practiceStatsR, examStatsR, practicedUnitsR] = await Promise.all([
      pool.query(`SELECT name, teacher, room, time, sched_type, custom_days FROM groups WHERE student_ids @> $1::jsonb`, [JSON.stringify([studentId])]),
      pool.query(
        `SELECT to_char(date,'YYYY-MM-DD') AS date, time, teacher FROM support_sessions
         WHERE student_id=$1 AND date >= $2 ORDER BY date, time LIMIT 1`,
        [studentId, todayISO]
      ),
      pool.query(
        `SELECT a.unit_ids FROM vocab_access a WHERE a.student_id=$1 AND a.used IS NOT TRUE ORDER BY a.created_at DESC LIMIT 1`,
        [studentId]
      ),
      computeStreak(studentId, nowTz),
      // Practice pass rate — the student's own free-practice attempts (vocab_practice_attempts).
      pool.query(`SELECT COUNT(*)::int total, COUNT(*) FILTER (WHERE passed)::int passed FROM vocab_practice_attempts WHERE student_id=$1`, [studentId]),
      // Unit test exam pass rate — formal, admin-graded tests (vocab_attempts, via a one-time code).
      pool.query(`SELECT COUNT(*)::int total, COUNT(*) FILTER (WHERE passed)::int passed FROM vocab_attempts WHERE student_id=$1`, [studentId]),
      // Units this student has actually PASSED (practice or formal exam) — a failed or
      // unattempted unit still needs recommending, only a pass clears it.
      pool.query(`
        SELECT unit_ids FROM vocab_practice_attempts WHERE student_id=$1 AND passed IS TRUE
        UNION ALL SELECT unit_ids FROM vocab_attempts WHERE student_id=$1 AND passed IS TRUE
      `, [studentId]),
    ]);

    let nextClass = null;
    for (const g of groupsR.rows) {
      const occ = nextClassOccurrence(g, nowTz);
      if (occ && (!nextClass || occ < nextClass.at)) {
        nextClass = { at: occ, groupName: g.name, teacher: g.teacher, room: g.room };
      }
    }

    let pendingTest = null;
    if (pendingR.rows[0]) {
      const unitIds = pendingR.rows[0].unit_ids || [];
      const unitsR = await pool.query('SELECT name FROM vocab_units WHERE id = ANY($1::text[])', [unitIds]);
      pendingTest = { unitNames: unitsR.rows.map(u => u.name) };
    }

    // Recommend the single next unit the student hasn't passed yet, in the same natural
    // (1A, 1B, 1C, 2A, …) order the practice picker uses — e.g. once they've passed 2B,
    // the next un-passed unit in sequence (2C, or whatever follows) is the recommendation.
    // A failed or never-attempted unit still counts as "not passed" and stays eligible.
    const passedIds = new Set(practicedUnitsR.rows.flatMap(r => r.unit_ids || []));
    const levelR = await pool.query(`SELECT level FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [studentId]);
    const level = levelR.rows[0]?.level || null;
    const unitsR = level
      ? await pool.query('SELECT id, name, level, words FROM vocab_units WHERE level=$1', [level])
      : await pool.query('SELECT id, name, level, words FROM vocab_units');
    const recommendedUnits = unitsR.rows
      .filter(u => !passedIds.has(u.id))
      .sort(naturalUnitCompare)
      .slice(0, 1)
      .map(u => ({ id: u.id, name: u.name, level: u.level, wordCount: (u.words || []).length }));

    res.json({
      streak,
      nextClass: nextClass ? { date: nextClass.at.toISOString().split('T')[0], time: String(nextClass.at.getHours()).padStart(2,'0')+':'+String(nextClass.at.getMinutes()).padStart(2,'0'), groupName: nextClass.groupName, teacher: nextClass.teacher, room: nextClass.room } : null,
      nextSupport: supportR.rows[0] || null,
      pendingTest,
      vocabStats: {
        practice: practiceStatsR.rows[0],
        exams: examStatsR.rows[0],
      },
      recommendedUnits,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Which units this student may practice: only units matching their group's level (same
// restriction admins already get when granting a graded test — see POST /api/vocab/access).
// Natural sort for unit names like "1A Welcome to the class", "2A ...", "10A ...":
// a plain string ORDER BY puts "10A" before "2A" since '1' < '2'. Pull the leading
// number out and compare numerically first, falling back to the rest of the name.
function naturalUnitCompare(a, b) {
  // Level first: when a student has no group (or their level doesn't match any unit's
  // level string) every level's units come back together, and without this a plain
  // number sort interleaves each level's "1A", "1B", ... one after another — three
  // different courses shuffled together looks like nothing is in order at all.
  const level = String(a.level || '').localeCompare(String(b.level || ''));
  if (level !== 0) return level;
  const parse = s => {
    const m = String(s || '').match(/^\s*(\d+)\s*(.*)$/);
    return m ? [parseInt(m[1], 10), m[2]] : [Infinity, String(s || '')];
  };
  const [an, arest] = parse(a.name);
  const [bn, brest] = parse(b.name);
  return an !== bn ? an - bn : arest.localeCompare(brest);
}

app.get('/api/student/vocab/units', async (req, res) => {
  try {
    const groupR = await pool.query(`SELECT lang, level FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [req.student.id]);
    const level = groupR.rows[0]?.level || null;
    const { rows } = level
      ? await pool.query('SELECT id, name, level, words FROM vocab_units WHERE level=$1', [level])
      : await pool.query('SELECT id, name, level, words FROM vocab_units');
    const units = rows.map(u => ({ id: u.id, name: u.name, level: u.level, wordCount: (u.words || []).length }));
    units.sort(naturalUnitCompare);
    res.json(units);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/student/vocab/practice/start', async (req, res) => {
  try {
    const unitIds = Array.isArray(req.body.unitIds) ? [...new Set(req.body.unitIds.filter(Boolean))] : [];
    if (!unitIds.length) return res.status(400).json({ error: 'Pick at least one unit.' });
    const [units, groupR] = await Promise.all([
      pool.query('SELECT id, level, words FROM vocab_units WHERE id = ANY($1::text[])', [unitIds]),
      pool.query(`SELECT lang, level FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [req.student.id]),
    ]);
    if (units.rows.length !== unitIds.length) return res.status(404).json({ error: 'One or more units were not found.' });
    const studentLevel = groupR.rows[0]?.level || null;
    if (studentLevel && units.rows.some(u => u.level !== studentLevel)) {
      return res.status(400).json({ error: `Pick units at your level (${studentLevel}).` });
    }
    const allWords = units.rows.flatMap(u => u.words || []);
    if (!allWords.length) return res.status(404).json({ error: 'These units have no words yet.' });
    const languagePair = groupR.rows[0]?.lang === 'UZ' ? 'ENG-UZ' : 'RU-ENG';
    const questionSet = buildQuestionSet(allWords, languagePair);
    const id = genVocabId('vprac');
    await pool.query(
      `INSERT INTO vocab_practice_sessions(id, student_id, unit_ids, language_pair, question_set) VALUES($1,$2,$3,$4,$5)`,
      [id, req.student.id, JSON.stringify(unitIds), languagePair, JSON.stringify(questionSet)]
    );
    const questions = questionSet.map((q, qid) => ({ qid, prompt: q.prompt, options: q.options }));
    res.json({ sessionId: id, questions, languagePair });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/student/vocab/practice/:sessionId/submit', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM vocab_practice_sessions WHERE id=$1 AND student_id=$2',
      [req.params.sessionId, req.student.id]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Practice session not found.' });
    const { score, total, passed, details } = scoreQuestionSet(row.question_set, req.body.answers);
    const attemptId = genVocabId('vpatt');
    await pool.query(
      `INSERT INTO vocab_practice_attempts(id, student_id, unit_ids, language_pair, score, total, passed) VALUES($1,$2,$3,$4,$5,$6,$7)`,
      [attemptId, req.student.id, JSON.stringify(row.unit_ids), row.language_pair, score, total, passed]
    );
    await pool.query('DELETE FROM vocab_practice_sessions WHERE id=$1', [row.id]);
    res.json({ ok: true, score, total, passed, details });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/student/vocab/history', async (req, res) => {
  try {
    const [attemptsR, unitsR] = await Promise.all([
      pool.query('SELECT * FROM vocab_practice_attempts WHERE student_id=$1 ORDER BY completed_at DESC LIMIT 100', [req.student.id]),
      pool.query('SELECT id, name FROM vocab_units'),
    ]);
    const unitNames = new Map(unitsR.rows.map(u => [u.id, u.name]));
    res.json(attemptsR.rows.map(t => ({
      id: t.id, unitIds: t.unit_ids || [],
      unitNames: (t.unit_ids || []).map(id => unitNames.get(id) || '(deleted unit)'),
      score: t.score, total: t.total, passed: t.passed, completedAt: t.completed_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/student/support/teachers', async (req, res) => {
  try {
    const [teachersR, groupR] = await Promise.all([
      pool.query("SELECT first_name, last_name, support_odd_start, support_odd_end, support_even_start, support_even_end, support_lang FROM users WHERE title='Support Teacher' OR roles @> '[\"Support Teacher\"]' ORDER BY first_name"),
      pool.query(`SELECT lang FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [req.student.id]),
    ]);
    const studentLang = groupR.rows[0]?.lang || null;
    const rows = teachersR.rows.filter(u => teacherLangMatches(u.support_lang, studentLang));
    res.json(rows.map(u => ({
      name: u.first_name + ' ' + u.last_name,
      odd:  u.support_odd_start  ? { start: u.support_odd_start,  end: u.support_odd_end  } : null,
      even: u.support_even_start ? { start: u.support_even_start, end: u.support_even_end } : null,
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Available slots for a given day + duration — the actual bookable (time, teacher) pairs
// once shift hours, existing bookings (both the per-teacher and the 2-slots-at-once cap),
// and past times are all accounted for. Lets the student just pick from what's open
// instead of guessing a time and getting rejected.
app.get('/api/student/support/slots', async (req, res) => {
  try {
    const date = String(req.query.date || '');
    const duration = Number(req.query.duration) === 60 ? 60 : 30;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid date.' });

    const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const todayISO = nowTz.toISOString().split('T')[0];
    const maxISO = studentMaxBookingDate(nowTz);
    if (date < todayISO || date > maxISO) return res.json([]);
    const isToday = date === todayISO;
    const nowMin = isToday ? nowTz.getHours() * 60 + nowTz.getMinutes() : 0;

    const [teachersR, sessionsR, groupR] = await Promise.all([
      pool.query("SELECT first_name, last_name, support_odd_start, support_odd_end, support_even_start, support_even_end, support_lang FROM users WHERE title='Support Teacher' OR roles @> '[\"Support Teacher\"]' ORDER BY first_name"),
      pool.query('SELECT time, duration, teacher FROM support_sessions WHERE date=$1', [date]),
      pool.query(`SELECT lang FROM groups WHERE student_ids @> to_jsonb($1::text) LIMIT 1`, [req.student.id]),
    ]);
    const studentLang = groupR.rows[0]?.lang || null;
    const dt = dateDayType(date);
    const existing = sessionsR.rows.map(s => ({ start: toMin(s.time), end: toMin(s.time) + Number(s.duration || 30), teacher: s.teacher }));

    const slots = [];
    for (const t of teachersR.rows) {
      if (!teacherLangMatches(t.support_lang, studentLang)) continue;
      const shiftStart = dt === 'odd' ? t.support_odd_start : dt === 'even' ? t.support_even_start : null;
      const shiftEnd   = dt === 'odd' ? t.support_odd_end   : dt === 'even' ? t.support_even_end   : null;
      if (!shiftStart) continue;
      const name = t.first_name + ' ' + t.last_name;
      const lo = toMin(shiftStart), hi = toMin(shiftEnd);
      for (let start = lo; start <= hi - duration; start += 30) {
        if (isToday && start <= nowMin) continue;
        const end = start + duration;
        const overlap = existing.filter(s => start < s.end && s.start < end);
        if (overlap.length >= 2) continue; // both concurrent slots taken
        if (overlap.some(s => s.teacher === name)) continue; // this teacher already busy
        const hh = String(Math.floor(start / 60)).padStart(2, '0'), mm = String(start % 60).padStart(2, '0');
        slots.push({ time: `${hh}:${mm}`, teacher: name });
      }
    }
    slots.sort((a, b) => a.time.localeCompare(b.time) || a.teacher.localeCompare(b.teacher));
    res.json(slots);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Active fine + "already booked today" — drives the booking UI's blocked/limit state.
app.get('/api/student/support/status', async (req, res) => {
  try {
    const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const todayISO = nowTz.toISOString().split('T')[0];
    const [fineR, todayR] = await Promise.all([
      pool.query('SELECT blocked_until FROM support_fines WHERE student_id=$1 AND blocked_until > NOW() ORDER BY blocked_until DESC LIMIT 1', [req.student.id]),
      pool.query("SELECT id, to_char(date,'YYYY-MM-DD') AS date, time, duration, teacher, theme, attended FROM support_sessions WHERE student_id=$1 AND date=$2", [req.student.id, todayISO]),
    ]);
    res.json({
      blockedUntil: fineR.rows[0]?.blocked_until || null,
      bookedToday: todayR.rows[0] || null,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/student/support/book', async (req, res) => {
  try {
    const { date, time, duration, teacher, theme } = req.body;
    const studentId = req.student.id;
    if (!date) return res.status(400).json({ error: 'Date is required.' });
    const nowTz = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Tashkent' }));
    const todayISO = nowTz.toISOString().split('T')[0];
    const maxISO = studentMaxBookingDate(nowTz);
    if (date < todayISO || date > maxISO) return res.status(409).json({ error: 'You can only book for today or up to 2 days ahead.' });
    // One session per day, on top of the shared shift/overlap/fine rules.
    const already = await pool.query('SELECT 1 FROM support_sessions WHERE student_id=$1 AND date=$2 LIMIT 1', [studentId, date]);
    if (already.rows.length) return res.status(409).json({ error: 'You already booked a support session today.' });
    const id = genVocabId('sup');
    await createSupportSession({ id, date, time, duration, teacher, studentId, theme });
    res.json({ ok: true });
  } catch(e) {
    if (e && e.status) return res.status(e.status).json({ error: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/student/support/history', async (req, res) => {
  try {
    // Cast date to text in SQL rather than letting node-postgres hand back a JS Date —
    // serializing that to JSON re-interprets it through the server process's local
    // timezone and can shift the calendar date by a day.
    const { rows } = await pool.query(
      "SELECT id, to_char(date,'YYYY-MM-DD') AS date, time, duration, teacher, theme, attended FROM support_sessions WHERE student_id=$1 ORDER BY date DESC, time DESC LIMIT 100",
      [req.student.id]
    );
    res.json(rows.map(s => ({ id: s.id, date: s.date, time: s.time, duration: s.duration, teacher: s.teacher, theme: s.theme, attended: s.attended })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Suggestions/complaints — always routed to the CEO (a notification is created for every
// CEO account), never visible to any other staff role.
app.post('/api/student/feedback', async (req, res) => {
  try {
    const type = req.body.type === 'complaint' ? 'complaint' : 'suggestion';
    const message = String(req.body.message || '').trim().slice(0, 2000);
    if (!message) return res.status(400).json({ error: 'Please write a message first.' });
    const id = crypto.randomUUID();
    const studentName = `${req.student.first_name} ${req.student.last_name}`;
    await pool.query(
      `INSERT INTO student_feedback(id, student_id, student_name, type, message) VALUES($1,$2,$3,$4,$5)`,
      [id, req.student.id, studentName, type, message]
    );
    const preview = message.length > 140 ? message.slice(0, 140) + '…' : message;
    await notifyCEOs('feedback', type === 'complaint' ? 'New complaint' : 'New suggestion', `${studentName}: ${preview}`, 'feedback.html');
    broadcast('feedback');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Public, unauthenticated: standalone vocab-test.html. Student enters the code an
// admin/teacher granted them. Bypassed in the /api auth middleware above.
app.get('/api/public/vocab/access/:code', async (req, res) => {
  try {
    const code = String(req.params.code || '').trim();
    const { rows } = await pool.query(`
      SELECT a.id, a.used, a.unit_ids, a.language_pair, s.first_name, s.last_name
      FROM vocab_access a
      JOIN students s ON s.id = a.student_id
      WHERE a.code = $1
    `, [code]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Invalid code.' });
    if (row.used) return res.status(410).json({ error: 'This code has already been used. Ask your admin for a new one.' });
    const units = await pool.query('SELECT name, words FROM vocab_units WHERE id = ANY($1::text[])', [row.unit_ids || []]);
    if (!units.rows.length) return res.status(404).json({ error: 'The unit(s) for this code no longer exist.' });
    const unitNames = units.rows.map(u => u.name);
    const wordCount = units.rows.reduce((sum, u) => sum + (u.words || []).length, 0);
    res.json({
      accessId: row.id, unitNames, languagePair: row.language_pair,
      wordCount, studentName: `${row.first_name} ${row.last_name}`
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Builds (or replays) the shuffled/mixed-direction question set for an access code.
// Each question is a full snapshot (word + accepted answers), taken once at first fetch,
// so accepted answers are never re-derived from (possibly since-edited) unit data, and
// are never sent to the client — only the prompt (+ multiple-choice options, if any) are.
app.get('/api/public/vocab/test/:accessId', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM vocab_access WHERE id=$1', [req.params.accessId]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Access not found.' });
    if (row.used) return res.status(410).json({ error: 'This test was already completed.' });

    let questionSet = row.question_set;
    if (!questionSet) {
      const units = await pool.query('SELECT words FROM vocab_units WHERE id = ANY($1::text[])', [row.unit_ids || []]);
      const allWords = units.rows.flatMap(u => u.words || []);
      if (!allWords.length) return res.status(404).json({ error: 'The unit(s) for this code no longer exist.' });
      // language_pair picks which of RU/UZ is shown; the student always answers in English.
      questionSet = buildQuestionSet(allWords, row.language_pair);
      await pool.query('UPDATE vocab_access SET question_set=$1 WHERE id=$2', [JSON.stringify(questionSet), req.params.accessId]);
    }
    const questions = questionSet.map((q, qid) => ({ qid, prompt: q.prompt, options: q.options }));
    res.json({ questions });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/public/vocab/test/:accessId/submit', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM vocab_access WHERE id=$1', [req.params.accessId]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Access not found.' });
    if (row.used) return res.status(410).json({ error: 'This test was already completed.' });
    if (!row.question_set) return res.status(400).json({ error: 'Test was never started.' });

    const { score, total, passed, details } = scoreQuestionSet(row.question_set, req.body.answers);
    const attemptId = genVocabId('vatt');
    await pool.query(
      `INSERT INTO vocab_attempts(id, access_id, student_id, unit_ids, score, total, passed, answers) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [attemptId, row.id, row.student_id, JSON.stringify(row.unit_ids), score, total, passed, JSON.stringify(details)]
    );
    await pool.query('UPDATE vocab_access SET used=TRUE, used_at=NOW() WHERE id=$1', [row.id]);
    broadcast('vocab');
    res.json({ ok: true, score, total, passed, details });
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
    // Upsert/clear only the specific students in this request — never wipe the whole day.
    // A blanket delete-then-reinsert here would let one save race another and silently
    // erase marks the sender's local copy didn't know about (e.g. from a concurrent
    // teacher/admin session, or a live-reload landing mid-edit).
    for (const r of records) {
      if (!r.status) {
        await pool.query(
          'DELETE FROM attendance WHERE group_id=$1 AND date=$2 AND student_id=$3',
          [req.params.groupId, req.params.date, r.studentId]
        );
      } else {
        await pool.query(
          `INSERT INTO attendance(group_id,date,student_id,status) VALUES($1,$2,$3,$4)
           ON CONFLICT(group_id,date,student_id) DO UPDATE SET status=$4`,
          [req.params.groupId, req.params.date, r.studentId, r.status]
        );
      }
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
    const actor = req.user ? req.user.last_name+' '+req.user.first_name : 'Someone';
    await notifyRole('staff', 'new_lead', 'New lead registered',
      `${lastName} ${firstName} registered by ${actor}`, 'leads.html', req.user?.id);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Public, unauthenticated: front-desk kiosk self-registration (register.html).
// Bypassed in the /api auth middleware above — keep this endpoint minimal and validated.
app.post('/api/public/lead-signup', async (req, res) => {
  try {
    const firstName = String(req.body.firstName || '').trim().slice(0, 80);
    const lastName = String(req.body.lastName || '').trim().slice(0, 80);
    const phoneStudent = String(req.body.phoneStudent || '').trim().slice(0, 20);
    const phoneFather = String(req.body.phoneFather || '').trim().slice(0, 20);
    const phoneMother = String(req.body.phoneMother || '').trim().slice(0, 20);
    const phoneOther = String(req.body.phoneOther || '').trim().slice(0, 20);
    const phoneCount = [phoneStudent, phoneFather, phoneMother, phoneOther].filter(Boolean).length;
    if (!firstName || !lastName || phoneCount < 2) {
      return res.status(400).json({ error: 'Name and at least 2 phone numbers are required.' });
    }
    const id = 'lead_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    // Drop self-registered leads into the "Tablet" sub-column of Registration, if staff have
    // created one — looked up by name so it keeps working if it's ever recreated/renamed.
    const tablet = await pool.query(
      `SELECT id FROM lead_containers WHERE status='Registration' AND name='Tablet' ORDER BY created_at LIMIT 1`
    );
    const subContainer = tablet.rows[0]?.id || null;
    await pool.query(
      `INSERT INTO leads(id,first_name,last_name,phone_student,phone_father,phone_mother,phone_other,notes,status,sub_container)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,'Registration',$9)`,
      [id, firstName, lastName, phoneStudent||null, phoneFather||null, phoneMother||null, phoneOther||null, 'Self-registered at front desk', subContainer]
    );
    await notifyRole('staff', 'new_lead', 'New lead registered',
      `${lastName} ${firstName} self-registered`, 'leads.html');
    broadcast('leads');
    res.json({ ok: true, leadId: id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Public, unauthenticated: saves the kiosk level-check test result onto the lead just created
// above. Scoped tightly — only touches current_level/test_result, and only while the lead is
// still sitting in Registration status, so it can't be used to edit an unrelated/older lead.
app.put('/api/public/lead-test/:id', async (req, res) => {
  try {
    const LEVELS = ['Beginner','Elementary','Pre-Intermediate','Intermediate'];
    const level = String(req.body.level || '');
    const testResult = String(req.body.testResult || '').trim().slice(0, 100);
    if (!LEVELS.includes(level)) return res.status(400).json({ error: 'Invalid level.' });
    const { rowCount } = await pool.query(
      `UPDATE leads SET current_level=$1, test_result=$2 WHERE id=$3 AND status='Registration'`,
      [level, testResult, req.params.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Lead not found.' });
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
      `INSERT INTO students(id,first_name,last_name,phone,phone_parent,phone_mother,phone_other,level,status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,'Active')`,
      [studentId, l.first_name, l.last_name, phone, l.phone_father, l.phone_mother, l.phone_other, l.current_level]
    );
    await pool.query(`UPDATE leads SET status='Student' WHERE id=$1`, [req.params.id]);
    const actor = req.user ? req.user.first_name + ' ' + req.user.last_name : null;
    await pool.query(
      `INSERT INTO lead_conversions(lead_id, student_id, converted_by) VALUES($1,$2,$3)`,
      [req.params.id, studentId, actor]
    ).catch(()=>{});
    // Carry over attendance marked while they were a trial lead (stored under the lead's id)
    // to the new student id, so it isn't orphaned once the lead record stops being referenced.
    await pool.query(
      `UPDATE attendance a SET student_id=$1 WHERE a.student_id=$2
       AND NOT EXISTS (SELECT 1 FROM attendance b WHERE b.student_id=$1 AND b.group_id=a.group_id AND b.date=a.date)`,
      [studentId, req.params.id]
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

/* LEAD CONTAINERS — synced across everyone with leads access, not per-browser */
app.get('/api/lead-containers', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, status, name, collapsed FROM lead_containers ORDER BY created_at');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lead-containers', async (req, res) => {
  try {
    const { id, status, name } = req.body;
    if (!status || !name || !name.trim()) return res.status(400).json({ error: 'Status and name are required.' });
    await pool.query('INSERT INTO lead_containers(id,status,name) VALUES($1,$2,$3)', [id, status, name.trim()]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/lead-containers/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM lead_containers WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found.' });
    const prev = rows[0];
    const name = req.body.name != null ? req.body.name.trim() : prev.name;
    const collapsed = req.body.collapsed != null ? !!req.body.collapsed : prev.collapsed;
    await pool.query('UPDATE lead_containers SET name=$1, collapsed=$2 WHERE id=$3', [name, collapsed, req.params.id]);
    broadcast('leads');
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/lead-containers/:id', async (req, res) => {
  try {
    await pool.query('UPDATE leads SET sub_container=NULL WHERE sub_container=$1', [req.params.id]);
    await pool.query('DELETE FROM lead_containers WHERE id=$1', [req.params.id]);
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
      pool.query("SELECT id,status,balance FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial') AND is_test IS NOT TRUE"),
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
    const myRolesGet = rolesLowerOf(me);
    const isAdminRole = TASK_PACKS.administration.match(myRolesGet);
    const isTeacherRole = TASK_PACKS.teachers.match(myRolesGet);
    const isSupportRole = TASK_PACKS.support.match(myRolesGet);
    const { rows } = await pool.query(
      `SELECT r.*,
        cu.first_name||' '||cu.last_name AS created_by_name,
        CASE WHEN r.assigned_to_id='administration' THEN 'Administration'
             WHEN r.assigned_to_id='teachers' THEN 'Teachers'
             WHEN r.assigned_to_id='support' THEN 'Support Teachers'
             ELSE au.first_name||' '||au.last_name END AS assigned_to_name
       FROM reminders r
       LEFT JOIN users cu ON cu.id = r.created_by_id
       LEFT JOIN users au ON au.id = r.assigned_to_id
       WHERE r.assigned_to_id=$1 OR r.created_by_id=$1
          OR (r.assigned_to_id='administration' AND $2)
          OR (r.assigned_to_id='teachers' AND $3)
          OR (r.assigned_to_id='support' AND $4)
       ORDER BY
         CASE r.status WHEN 'overdue' THEN 0 WHEN 'pending' THEN 1 WHEN 'in_process' THEN 2 ELSE 3 END,
         r.due_date ASC NULLS LAST, r.created_at DESC`,
      [me.id, isAdminRole, isTeacherRole, isSupportRole]);
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
    const cRoles = rolesLowerOf(req.user);
    const cIsAdmin = TASK_PACKS.administration.match(cRoles);
    const cIsTeacher = TASK_PACKS.teachers.match(cRoles);
    const cIsSupport = TASK_PACKS.support.match(cRoles);
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS n FROM reminders
       WHERE (assigned_to_id=$1 OR (assigned_to_id='administration' AND $2)
              OR (assigned_to_id='teachers' AND $3) OR (assigned_to_id='support' AND $4))
         AND status NOT IN ('completed')`,
      [req.user.id, cIsAdmin, cIsTeacher, cIsSupport]
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
             WHEN r.assigned_to_id='teachers' THEN 'Teachers'
             WHEN r.assigned_to_id='support' THEN 'Support Teachers'
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
    const PACK_QUERIES = {
      administration: `SELECT id FROM users WHERE (title IN ('Admin','Head Admin','Manager') OR roles @> '["Admin"]'::jsonb OR roles @> '["Head Admin"]'::jsonb OR roles @> '["Manager"]'::jsonb) AND id<>$1`,
      teachers:        `SELECT id FROM users WHERE (title='Teacher' OR roles @> '["Teacher"]'::jsonb) AND id<>$1`,
      support:         `SELECT id FROM users WHERE (title='Support Teacher' OR roles @> '["Support Teacher"]'::jsonb) AND id<>$1`,
    };
    if (PACK_QUERIES[finalAssignee]) {
      const { rows: packUsers } = await pool.query(PACK_QUERIES[finalAssignee], [me.id]).catch(()=>({rows:[]}));
      for (const u of packUsers) await createNotif(u.id, 'task_assigned', `New task for ${TASK_PACKS[finalAssignee].label}`,
        `"${title}" assigned by ${me.last_name} ${me.first_name}`, 'reminders.html');
    } else if (finalAssignee !== me.id) {
      await createNotif(finalAssignee, 'task_assigned', 'New task assigned to you',
        `"${title}" assigned by ${me.last_name} ${me.first_name}`, 'reminders.html');
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
    const statusRoles = rolesLowerOf(me);
    const pack = TASK_PACKS[task.assigned_to_id];
    const isPackTask = !!pack;
    if (task.status === 'overdue' && !isCEO) return res.status(403).json({ error: 'Overdue tasks are locked.' });
    if (!isPackTask && task.assigned_to_id !== me.id && !isCEO)
      return res.status(403).json({ error: 'Only assignee can update status.' });
    if (isPackTask && !pack.match(statusRoles) && !isCEO)
      return res.status(403).json({ error: `Only ${pack.label} can update this task.` });
    const { rows: tr } = await pool.query(`SELECT title, created_by_id, due_date, due_time, priority, assigned_to_id, repeat_every, note FROM reminders WHERE id=$1`, [req.params.id]);
    // Claim pack task when moving to in_process
    if (isPackTask && status === 'in_process') {
      await pool.query(`UPDATE reminders SET status=$1, assigned_to_id=$2 WHERE id=$3`, [status, me.id, req.params.id]);
    } else {
      await pool.query(`UPDATE reminders SET status=$1 WHERE id=$2`, [status, req.params.id]);
    }
    if (tr.length && tr[0].created_by_id !== me.id) {
      const statusLabel = { in_process:'In Process', completed:'Completed' }[status] || status;
      await createNotif(tr[0].created_by_id, 'task_status', 'Task status updated',
        `"${tr[0].title}" marked as ${statusLabel} by ${me.last_name} ${me.first_name}`, 'reminders.html');
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
    broadcast('reminders');
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
    broadcast('reminders');
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
    broadcast('reminders');
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

/* STUDENT FEEDBACK (suggestions/complaints) — CEO only, gated by requiredPerm('feedback') above */
app.get('/api/feedback', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM student_feedback ORDER BY created_at DESC`);
    res.json(rows.map(r => ({
      id: r.id, studentId: r.student_id, studentName: r.student_name,
      type: r.type, message: r.message, read: r.read, createdAt: r.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/feedback/:id/read', async (req, res) => {
  try {
    await pool.query(`UPDATE student_feedback SET read=TRUE WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/feedback/:id', async (req, res) => {
  try {
    await pool.query(`DELETE FROM student_feedback WHERE id=$1`, [req.params.id]);
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
const BACKUP_TABLES = [
  'students', 'groups', 'invoices', 'leads', 'users', 'reminders', 'activity',
  'attendance', 'student_history', 'student_comments', 'student_calls',
  'group_comments', 'lead_calls', 'lead_conversions', 'support_sessions',
  'support_fines', 'notifications', 'pricing', 'spendings', 'custom_levels',
  'archive_reasons', 'teachers', 'student_feedback',
];
app.get('/api/backup', async (req, res) => {
  try {
    const userRoles = Array.isArray(req.user.roles) && req.user.roles.length ? req.user.roles : [req.user.title];
    if (!userRoles.includes('CEO')) return res.status(403).json({ error: 'Only CEO can download backups.' });
    const wb = new ExcelJS.Workbook();
    for (const t of BACKUP_TABLES) {
      const { rows } = await pool.query(`SELECT * FROM ${t}`);
      const data = t === 'users' ? rows.map(({ password, ...rest }) => rest) : rows;
      const sheet = wb.addWorksheet(t.slice(0, 31));
      if (!data.length) continue;
      const cols = Object.keys(data[0]);
      sheet.columns = cols.map(c => ({ header: c, key: c, width: 18 }));
      sheet.getRow(1).font = { bold: true };
      for (const row of data) {
        const flat = {};
        for (const c of cols) {
          const v = row[c];
          flat[c] = (v !== null && typeof v === 'object' && !(v instanceof Date)) ? JSON.stringify(v) : v;
        }
        sheet.addRow(flat);
      }
    }
    const filename = `tommylc-backup-${new Date().toISOString().slice(0,10)}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    await wb.xlsx.write(res);
    res.end();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

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
      pool.query("SELECT id, status, balance FROM students WHERE archived IS NOT TRUE AND status NOT IN ('Lead','Trial') AND is_test IS NOT TRUE"),
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

