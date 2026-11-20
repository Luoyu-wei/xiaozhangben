const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let db = { users: {}, expenses: {}, sessions: {} };
try {
    if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { console.error('读取数据失败，使用空库', e); }
const saveDB = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- 工具 ---------- */
const hashPass = (pw, salt) =>
    crypto.scryptSync(pw, salt, 64).toString('hex');

const parseCookies = req => {
    const out = {};
    (req.headers.cookie || '').split(';').forEach(p => {
        const i = p.indexOf('=');
        if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
    });
    return out;
};

const auth = (req, res, next) => {
    const token = parseCookies(req).sid;
    const username = token && db.sessions[token];
    if (!username || !db.users[username])
        return res.status(401).json({ error: '未登录' });
    req.username = username;
    next();
};

/* ---------- 注册 ---------- */
app.post('/api/register', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || !/^\S{2,16}$/.test(username))
        return res.status(400).json({ error: '用户名需为 2-16 个字符且不含空格' });
    if (typeof password !== 'string' || password.length < 4)
        return res.status(400).json({ error: '密码至少 4 位' });
    if (db.users[username])
        return res.status(409).json({ error: '该用户名已被注册' });

    const salt = crypto.randomBytes(16).toString('hex');
    db.users[username] = { salt, hash: hashPass(password, salt), created: Date.now() };
    db.expenses[username] = [];
    saveDB();
    res.json({ ok: true });
});

/* ---------- 登录 ---------- */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    const user = db.users[username];
    if (!user || user.hash !== hashPass(String(password || ''), user.salt))
        return res.status(401).json({ error: '用户名或密码错误' });

    const token = crypto.randomBytes(24).toString('hex');
    db.sessions[token] = username;
    saveDB();
    res.setHeader('Set-Cookie',
        `sid=${token}; HttpOnly; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax`);
    res.json({ username });
});

/* ---------- 登出 ---------- */
app.post('/api/logout', (req, res) => {
    const token = parseCookies(req).sid;
    if (token) { delete db.sessions[token]; saveDB(); }
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
    res.json({ ok: true });
});

/* ---------- 当前用户 ---------- */
app.get('/api/me', auth, (req, res) => res.json({ username: req.username }));

/* ---------- 记录列表 ---------- */
app.get('/api/expenses', auth, (req, res) => {
    res.json(db.expenses[req.username] || []);
});

/* ---------- 新增记录 ---------- */
app.post('/api/expenses', auth, (req, res) => {
    const { amount, category, date, note } = req.body || {};
    const num = Number(amount);
    if (!(num > 0)) return res.status(400).json({ error: '金额不正确' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(date || '')))
        return res.status(400).json({ error: '日期格式不正确' });

    const item = {
        id: crypto.randomBytes(8).toString('hex'),
        amount: Math.round(num * 100) / 100,
        category: String(category || '其他').slice(0, 10),
        date,
        note: String(note || '').slice(0, 30),
        createdAt: Date.now()
    };
    (db.expenses[req.username] = db.expenses[req.username] || []).push(item);
    saveDB();
    res.json(item);
});

/* ---------- 删除记录 ---------- */
app.delete('/api/expenses/:id', auth, (req, res) => {
    const list = db.expenses[req.username] || [];
    db.expenses[req.username] = list.filter(x => x.id !== req.params.id);
    saveDB();
    res.json({ ok: true });
});

app.listen(PORT, () => console.log(`✅ 小账本已启动: http://localhost:${PORT}`));