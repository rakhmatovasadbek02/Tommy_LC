const express  = require('express');
const { Pool } = require('pg');
const path     = require('path');
const cors     = require('cors');

const app  = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
    `ALTER TABLE teachers ADD COLUMN IF NOT EXISTS password TEXT`,
    `ALTER TABLE leads ADD COLUMN IF NOT EXISTS sub_container TEXT`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS balance NUMERIC DEFAULT 0`,
    `ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_parent TEXT`,
  ];
  for (const sql of alters) {
    await pool.query(sql).catch(() => {});
  }

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

  // Null out group teacher names that no longer exist in the teachers table
  try {
    await pool.query(`
      UPDATE groups SET teacher = NULL
      WHERE teacher IS NOT NULL
      AND teacher NOT IN (SELECT first_name || ' ' || last_name FROM teachers)
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
    await pool.query(`
      INSERT INTO users (id, first_name, last_name, phone, password, role, avatar)
      VALUES ('u1','Admin','TommyLC','90 000 00 01','admin123','CEO','AT')
      ON CONFLICT DO NOTHING
    `);
    console.log('Seeded default CEO: phone=90 000 00 01  password=admin123');
  }

  console.log('Database ready');
}

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
    res.json({ id: u.id, name: u.first_name+' '+u.last_name, role: u.role, avatar: u.avatar, phone: u.phone });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* USERS */
app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users ORDER BY created_at');
    res.json(rows.map(u => ({
      id: u.id, firstName: u.first_name, lastName: u.last_name,
      name: u.first_name+' '+u.last_name, phone: u.phone, role: u.role, avatar: u.avatar
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', async (req, res) => {
  try {
    const { id, firstName, lastName, phone, password, role } = req.body;
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    await pool.query(
      'INSERT INTO users(id,first_name,last_name,phone,password,role,avatar) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [id, firstName, lastName, phone, password, role, avatar]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, password, role } = req.body;
    const avatar = (firstName[0]+(lastName[0]||'')).toUpperCase();
    if (password) {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,password=$4,role=$5,avatar=$6 WHERE id=$7',
        [firstName, lastName, phone, password, role, avatar, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET first_name=$1,last_name=$2,phone=$3,role=$4,avatar=$5 WHERE id=$6',
        [firstName, lastName, phone, role, avatar, req.params.id]
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
      pool.query('SELECT * FROM students ORDER BY created_at DESC'),
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
    const { id, firstName, lastName, phone, phoneParent, level, status, exam, examDate, notes } = req.body;
    await pool.query(
      'INSERT INTO students(id,first_name,last_name,phone,phone_parent,level,status,exam,exam_date,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [id, firstName, lastName, phone||null, phoneParent||null, level||null, status||'Active', exam||null, examDate||null, notes||null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/students/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, phoneParent, level, status, exam, examDate, notes } = req.body;
    await pool.query(
      'UPDATE students SET first_name=$1,last_name=$2,phone=$3,phone_parent=$4,level=$5,status=$6,exam=$7,exam_date=$8,notes=$9 WHERE id=$10',
      [firstName, lastName, phone||null, phoneParent||null, level||null, status||'Active', exam||null, examDate||null, notes||null, req.params.id]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/students/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM students WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


/* STUDENT DETAIL endpoints */
app.get('/api/students/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM students WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    const s = rows[0];
    res.json({ id: s.id, firstName: s.first_name, lastName: s.last_name,
      phone: s.phone, phoneParent: s.phone_parent,
      level: s.level, status: s.status, balance: Number(s.balance||0),
      exam: s.exam, examDate: s.exam_date, notes: s.notes, createdAt: s.created_at });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Adjust balance (add payment)
app.post('/api/students/:id/payment', async (req, res) => {
  try {
    const { amount, paymentType, groupId, desc, notes } = req.body;
    const num = Number(amount);
    // Update balance
    await pool.query('UPDATE students SET balance=balance+$1 WHERE id=$2', [num, req.params.id]);
    // Create invoice
    const id = 'inv-' + Date.now();
    const number = 'INV-' + Date.now().toString().slice(-6);
    const now = new Date();
    const month = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0');
    await pool.query(
      `INSERT INTO invoices(id,number,student_id,group_id,month,description,total,status,payment_type,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7,'Paid',$8,$9)`,
      [id, number, req.params.id, groupId||null, month, desc||'Payment', num, paymentType||'Cash', notes||null]
    );
    res.json({ ok: true, newBalance: num });
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
      notes: i.notes, createdAt: i.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* TEACHERS */
app.get('/api/teachers', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,first_name,last_name,phone,status,created_at FROM teachers ORDER BY created_at DESC');
    res.json(rows.map(t => ({
      id: t.id, firstName: t.first_name, lastName: t.last_name,
      phone: t.phone, status: t.status, createdAt: t.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/teachers', async (req, res) => {
  try {
    const { id, firstName, lastName, phone, password, status } = req.body;
    await pool.query(
      'INSERT INTO teachers(id,first_name,last_name,phone,password,status) VALUES($1,$2,$3,$4,$5,$6)',
      [id, firstName, lastName, phone||null, password||null, status||'Active']
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/teachers/:id', async (req, res) => {
  try {
    const { firstName, lastName, phone, password, status } = req.body;
    const newName = `${firstName} ${lastName}`;
    const old = await pool.query('SELECT first_name, last_name FROM teachers WHERE id=$1', [req.params.id]);
    const oldName = old.rows[0] ? `${old.rows[0].first_name} ${old.rows[0].last_name}` : null;
    if (password) {
      await pool.query(
        'UPDATE teachers SET first_name=$1,last_name=$2,phone=$3,password=$4,status=$5 WHERE id=$6',
        [firstName, lastName, phone||null, password, status||'Active', req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE teachers SET first_name=$1,last_name=$2,phone=$3,status=$4 WHERE id=$5',
        [firstName, lastName, phone||null, status||'Active', req.params.id]
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
    const old = await pool.query('SELECT first_name, last_name FROM teachers WHERE id=$1', [req.params.id]);
    if (old.rows[0]) {
      const name = `${old.rows[0].first_name} ${old.rows[0].last_name}`;
      await pool.query('UPDATE groups SET teacher=NULL WHERE teacher=$1', [name]);
    }
    await pool.query('DELETE FROM teachers WHERE id=$1', [req.params.id]);
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
      notes: i.notes, createdAt: i.created_at
    })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/invoices', async (req, res) => {
  try {
    const { id, number, studentId, groupId, level, month, desc, total, dueDate, status, paymentType, notes } = req.body;
    await pool.query(
      `INSERT INTO invoices(id,number,student_id,group_id,level,month,description,total,due_date,status,payment_type,notes)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, number, studentId, groupId||null, level||null, month||null, desc||null,
       total||0, dueDate||null, status||'Pending', paymentType||'Cash', notes||null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/invoices/:id', async (req, res) => {
  try {
    const { studentId, groupId, level, month, desc, total, dueDate, status, paymentType, notes } = req.body;
    await pool.query(
      `UPDATE invoices SET student_id=$1,group_id=$2,level=$3,month=$4,description=$5,
       total=$6,due_date=$7,status=$8,payment_type=$9,notes=$10 WHERE id=$11`,
      [studentId, groupId||null, level||null, month||null, desc||null,
       total||0, dueDate||null, status||'Pending', paymentType||'Cash', notes||null, req.params.id]
    );
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
    await pool.query('DELETE FROM invoices WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ATTENDANCE */
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
    const phone = l.phone_student || l.phone_father || l.phone_mother || l.phone_other || null;
    await pool.query(
      `INSERT INTO students(id,first_name,last_name,phone,level,status)
       VALUES($1,$2,$3,$4,$5,'Active')
       ON CONFLICT(id) DO UPDATE SET first_name=$2,last_name=$3,phone=$4,level=$5,status='Active'`,
      [l.id, l.first_name, l.last_name, phone, l.current_level]
    );
    await pool.query(`UPDATE leads SET status='Student' WHERE id=$1`, [req.params.id]);
    // Add to group student_ids now that they are a real student
    if (l.group_id) {
      const grp = await pool.query('SELECT student_ids FROM groups WHERE id=$1', [l.group_id]);
      if (grp.rows[0]) {
        const ids = grp.rows[0].student_ids || [];
        if (!ids.includes(l.id)) {
          ids.push(l.id);
          await pool.query('UPDATE groups SET student_ids=$1 WHERE id=$2', [JSON.stringify(ids), l.group_id]);
        }
      }
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/leads/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM leads WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
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
initDB().then(() => app.listen(PORT, () => console.log(`TommyLC running on port ${PORT}`)));