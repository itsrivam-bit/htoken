'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 8765;
const HOST = process.env.HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
const ROOT_DIR = __dirname;
const DATA_FILE = process.env.DATA_FILE
    ? path.resolve(process.env.DATA_FILE)
    : path.join(ROOT_DIR, 'data.json');
const INDEX_FILE = path.join(ROOT_DIR, 'index.html');

const DEFAULT_ADMIN_PASS_HASH = '4f312b6805d09bb67ddb25314c7d9d049db0b7777a592d32cb1198f3d6909f78';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH
    || (process.env.ADMIN_PASS
        ? crypto.createHash('sha256').update(String(process.env.ADMIN_PASS), 'utf8').digest('hex')
        : DEFAULT_ADMIN_PASS_HASH);
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB JSON limit
const MAX_STORED_TXT_CHARS = 50000;
const USER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const DEFAULT_STATE = () => ({
    users: [],
    sessions: [],
    submissions: [],
    hwids: [],
    vortexKeys: [],
    config: {
        botToken: process.env.BOT_TOKEN || '9210440740:AAHzR1hWD10FIqPMz3qYLij0NqWsCLuHZBc',
        chatId: process.env.CHAT_ID || '8732686137'
    }
});

let state = loadInitialState();
let writeQueue = Promise.resolve();

function loadInitialState() {
    try {
        fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
        if (!fs.existsSync(DATA_FILE)) {
            const init = DEFAULT_STATE();
            fs.writeFileSync(DATA_FILE, JSON.stringify(init, null, 2), 'utf8');
            return init;
        }
        const raw = fs.readFileSync(DATA_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        const def = DEFAULT_STATE();
        return {
            users: Array.isArray(parsed.users) ? parsed.users : [],
            sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
            submissions: Array.isArray(parsed.submissions) ? parsed.submissions : [],
            hwids: Array.isArray(parsed.hwids) ? parsed.hwids : [],
            vortexKeys: Array.isArray(parsed.vortexKeys) ? parsed.vortexKeys : [],
            config: parsed.config && parsed.config.botToken && parsed.config.chatId
                ? { botToken: String(parsed.config.botToken), chatId: String(parsed.config.chatId) }
                : def.config
        };
    } catch (err) {
        console.error('Failed to read data.json, starting fresh:', err.message);
        return DEFAULT_STATE();
    }
}

function saveState() {
    const now = Date.now();
    state.sessions = state.sessions.filter(s => s && s.expiresAt > now);
    const payload = JSON.stringify(state, null, 2);
    const tmpFile = DATA_FILE + '.tmp';
    writeQueue = writeQueue.then(async () => {
        await fs.promises.mkdir(path.dirname(DATA_FILE), { recursive: true });
        await fs.promises.writeFile(tmpFile, payload, 'utf8');
        await fs.promises.rename(tmpFile, DATA_FILE);
    }).catch(err => {
        console.error('Failed to write data.json:', err.message);
    });
    return writeQueue;
}

function genId() {
    return Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
    const parts = String(stored || '').split(':');
    if (parts.length !== 2) return false;
    const [salt, expectedHex] = parts;
    const derived = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function verifyAdminPassword(password) {
    const actual = crypto.createHash('sha256').update(String(password || ''), 'utf8').digest();
    const expected = Buffer.from(ADMIN_PASS_HASH, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function createSession(role, userId = null) {
    const token = crypto.randomBytes(32).toString('hex');
    const ttl = role === 'admin' ? ADMIN_SESSION_TTL_MS : USER_SESSION_TTL_MS;
    state.sessions.push({
        token,
        role,
        userId,
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + ttl
    });
    return token;
}

function getBearerToken(req) {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
}

function getSessionByRole(req, role) {
    const token = getBearerToken(req);
    if (!token) return null;
    const now = Date.now();
    const session = state.sessions.find(s => s.token === token && s.role === role && s.expiresAt > now);
    if (!session) return null;
    if (role === 'user') {
        const user = state.users.find(u => u.id === session.userId);
        return user ? { session, user } : null;
    }
    return { session };
}

function sendJson(res, status, data) {
    const body = JSON.stringify(data);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
    });
    res.end(body);
}

function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];
        req.on('data', chunk => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                reject(new Error('PAYLOAD_TOO_LARGE'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (chunks.length === 0) return resolve({});
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(new Error('INVALID_JSON'));
            }
        });
        req.on('error', reject);
    });
}

function publicUser(user) {
    return { id: user.id, name: user.name, username: user.username, createdAt: user.createdAt };
}

async function handleApi(req, res, pathname, searchParams) {
    const method = req.method.toUpperCase();

    // --- User Auth ---
    if (pathname === '/api/auth/register' && method === 'POST') {
        const body = await readJsonBody(req);
        const name = String(body.name || '').trim();
        const usernameRaw = String(body.username || '').trim();
        const username = usernameRaw.toLowerCase();
        const password = String(body.password || '');

        if (name.length < 2 || name.length > 60) {
            return sendJson(res, 400, { error: 'الاسم يجب أن يكون من 2 إلى 60 حرفاً.' });
        }
        if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
            return sendJson(res, 400, { error: 'اسم المستخدم يجب أن يكون بالإنجليزية (3 إلى 32 حرف/رقم بدون مسافات).' });
        }
        if (password.length < 4 || password.length > 128) {
            return sendJson(res, 400, { error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل.' });
        }
        if (state.users.some(u => u.username === username)) {
            return sendJson(res, 409, { error: 'اسم المستخدم مسجل بالفعل، اختر اسماً آخر.' });
        }

        const nowIso = new Date().toISOString();
        const user = {
            id: genId(),
            name,
            username,
            passwordHash: hashPassword(password),
            createdAt: nowIso,
            lastLoginAt: nowIso
        };
        state.users.push(user);
        const token = createSession('user', user.id);
        await saveState();
        return sendJson(res, 201, { token, user: publicUser(user) });
    }

    if (pathname === '/api/auth/login' && method === 'POST') {
        const body = await readJsonBody(req);
        const username = String(body.username || '').trim().toLowerCase();
        const password = String(body.password || '');
        const user = state.users.find(u => u.username === username);
        if (!user || !verifyPassword(password, user.passwordHash)) {
            return sendJson(res, 401, { error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
        }
        user.lastLoginAt = new Date().toISOString();
        const token = createSession('user', user.id);
        await saveState();
        return sendJson(res, 200, { token, user: publicUser(user) });
    }

    if (pathname === '/api/auth/me' && method === 'GET') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'غير مسجل الدخول.' });
        if (!auth.user.lastLoginAt) {
            auth.user.lastLoginAt = auth.session.createdAt || auth.user.createdAt;
            await saveState();
        }
        return sendJson(res, 200, { user: publicUser(auth.user) });
    }

    if (pathname === '/api/auth/logout' && method === 'POST') {
        const token = getBearerToken(req);
        if (token) {
            state.sessions = state.sessions.filter(s => s.token !== token);
            await saveState();
        }
        return sendJson(res, 200, { ok: true });
    }

    // --- Bot Config for Authenticated Submissions ---
    if (pathname === '/api/config/bot' && method === 'GET') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });
        return sendJson(res, 200, state.config);
    }

    // --- User Submissions ---
    if (pathname === '/api/submissions/mine' && method === 'GET') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });
        const mine = state.submissions.filter(s => s.userId === auth.user.id);
        const totalValid = mine.reduce((acc, s) => acc + (typeof s.valid === 'number' ? s.valid : 0), 0);
        const totalMailLocked = mine.reduce((acc, s) => acc + (typeof s.mailLocked === 'number' ? s.mailLocked : 0), 0);
        return sendJson(res, 200, {
            submissions: mine,
            stats: { totalFiles: mine.length, totalValid, totalMailLocked }
        });
    }

    if (pathname === '/api/submissions' && method === 'POST') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });
        const body = await readJsonBody(req);
        const cash = String(body.cash || '').trim();
        const tool = String(body.tool || '').trim();
        const fileName = String(body.fileName || '').trim();
        const fileSize = Number(body.fileSize) || 0;
        const notes = String(body.notes || '').trim() || 'لا يوجد';
        const timestampAr = String(body.timestampAr || '').trim() || new Date().toLocaleString('ar-EG');

        if (!cash || !tool || !fileName) {
            return sendJson(res, 400, { error: 'بيانات التسليم غير مكتملة.' });
        }

        const valid = body.valid === null || body.valid === undefined ? null : Number(body.valid);
        const mailLocked = body.mailLocked === null || body.mailLocked === undefined ? null : Number(body.mailLocked);
        if ((valid !== null && (!Number.isInteger(valid) || valid < 0)) ||
            (mailLocked !== null && (!Number.isInteger(mailLocked) || mailLocked < 0))) {
            return sendJson(res, 400, { error: 'قيم الفحص غير صالحة.' });
        }

        const rawContent = String(body.fileContent || '');
        const record = {
            id: genId(),
            userId: auth.user.id,
            username: auth.user.username,
            name: auth.user.name,
            cash,
            tool,
            valid,
            mailLocked,
            notes,
            fileName,
            fileSize,
            fileContent: rawContent.slice(0, MAX_STORED_TXT_CHARS),
            fileTruncated: Boolean(body.fileTruncated) || rawContent.length > MAX_STORED_TXT_CHARS,
            timestampAr,
            createdAt: new Date().toISOString()
        };
        state.submissions.unshift(record);
        await saveState();
        return sendJson(res, 201, { ok: true, submission: record });
    }

    // --- User HWID Activation Requests ---
    if (pathname === '/api/hwid/request' && method === 'POST') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });

        const body = await readJsonBody(req);
        const hwid = String(body.hwid || '').trim();
        const tool = String(body.tool || '').trim();

        if (hwid.length < 4 || hwid.length > 200) {
            return sendJson(res, 400, { error: 'يرجى إدخال كود HWID صحيح.' });
        }
        if (tool.length < 1 || tool.length > 80) {
            return sendJson(res, 400, { error: 'يرجى إدخال اسم التول.' });
        }

        const existing = state.hwids.find(h =>
            h.hwid.toLowerCase() === hwid.toLowerCase() &&
            String(h.tool || '').toLowerCase() === tool.toLowerCase()
        );
        if (existing) {
            return sendJson(res, 200, { ok: true, duplicate: true, record: existing });
        }

        const record = {
            id: genId(),
            userId: auth.user.id,
            userName: auth.user.name,
            username: auth.user.username,
            hwid,
            tool,
            status: 'pending',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        state.hwids.unshift(record);
        await saveState();
        return sendJson(res, 201, { ok: true, duplicate: false, record });
    }

    if (pathname === '/api/hwid/mine' && method === 'GET') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'غير مسجل الدخول.' });
        const mine = state.hwids.filter(h => h.userId === auth.user.id);
        return sendJson(res, 200, { hwids: mine });
    }

    // --- Vortex Keys (Worker Request & Status) ---
    if (pathname === '/api/vortex/status' && method === 'GET') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });
        const availableCount = state.vortexKeys.filter(k => k.status === 'available').length;
        const myKeys = state.vortexKeys
            .filter(k => k.claimedByUserId === auth.user.id)
            .sort((a, b) => String(b.claimedAt || '').localeCompare(String(a.claimedAt || '')));
        return sendJson(res, 200, { availableCount, myKeys });
    }

    if (pathname === '/api/vortex/claim' && method === 'POST') {
        const auth = getSessionByRole(req, 'user');
        if (!auth) return sendJson(res, 401, { error: 'يرجى تسجيل الدخول أولاً.' });
        const nextKey = state.vortexKeys.find(k => k.status === 'available');
        if (!nextKey) {
            return sendJson(res, 409, { error: 'غير متوفر الآن', availableCount: 0 });
        }
        // Mutate synchronously before saveState so concurrent claims never get the same key
        nextKey.status = 'claimed';
        nextKey.claimedByUserId = auth.user.id;
        nextKey.claimedByName = auth.user.name;
        nextKey.claimedByUsername = auth.user.username;
        nextKey.claimedAt = new Date().toISOString();
        const availableCount = state.vortexKeys.filter(k => k.status === 'available').length;
        await saveState();
        return sendJson(res, 200, { ok: true, key: nextKey, availableCount });
    }

    // --- Admin Auth & Protected Endpoints ---
    if (pathname === '/api/admin/login' && method === 'POST') {
        const body = await readJsonBody(req);
        if (!verifyAdminPassword(body.password)) {
            return sendJson(res, 401, { error: 'كلمة المرور غير صحيحة' });
        }
        const token = createSession('admin');
        await saveState();
        return sendJson(res, 200, { token });
    }

    if (pathname.startsWith('/api/admin/')) {
        const adminAuth = getSessionByRole(req, 'admin');
        if (!adminAuth) {
            return sendJson(res, 401, { error: 'انتهت جلسة الأدمن أو غير مصرح.' });
        }

        if (pathname === '/api/admin/logout' && method === 'POST') {
            state.sessions = state.sessions.filter(s => s.token !== adminAuth.session.token);
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        if (pathname === '/api/admin/submissions' && method === 'GET') {
            return sendJson(res, 200, { submissions: state.submissions });
        }

        if (pathname === '/api/admin/submissions' && method === 'DELETE') {
            state.submissions = [];
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        const subMatch = pathname.match(/^\/api\/admin\/submissions\/([^/]+)$/);
        if (subMatch && method === 'DELETE') {
            const id = decodeURIComponent(subMatch[1]);
            state.submissions = state.submissions.filter(s => s.id !== id);
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        if (pathname === '/api/admin/hwids' && method === 'GET') {
            return sendJson(res, 200, { hwids: state.hwids });
        }

        const hwidMatch = pathname.match(/^\/api\/admin\/hwids\/([^/]+)$/);
        if (hwidMatch && method === 'PATCH') {
            const id = decodeURIComponent(hwidMatch[1]);
            const body = await readJsonBody(req);
            const nextStatus = String(body.status || '');
            if (!['pending', 'active', 'rejected'].includes(nextStatus)) {
                return sendJson(res, 400, { error: 'حالة غير صالحة.' });
            }
            const item = state.hwids.find(h => h.id === id);
            if (!item) return sendJson(res, 404, { error: 'الطلب غير موجود.' });
            item.status = nextStatus;
            item.updatedAt = new Date().toISOString();
            await saveState();
            return sendJson(res, 200, { ok: true, record: item });
        }

        if (hwidMatch && method === 'DELETE') {
            const id = decodeURIComponent(hwidMatch[1]);
            state.hwids = state.hwids.filter(h => h.id !== id);
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        // --- Admin Vortex Keys Management ---
        if (pathname === '/api/admin/vortex' && method === 'GET') {
            return sendJson(res, 200, { keys: state.vortexKeys });
        }

        if (pathname === '/api/admin/vortex' && method === 'POST') {
            const body = await readJsonBody(req);
            const rawLines = Array.isArray(body.keys)
                ? body.keys
                : String(body.keysText || '').split(/[\r\n,]+/);
            const existingSet = new Set(state.vortexKeys.map(k => k.key));
            let addedCount = 0;
            let skippedDuplicates = 0;

            for (const raw of rawLines) {
                const key = String(raw || '').trim();
                if (!key) continue;
                if (existingSet.has(key)) {
                    skippedDuplicates++;
                    continue;
                }
                existingSet.add(key);
                state.vortexKeys.push({
                    id: genId(),
                    key,
                    status: 'available',
                    createdAt: new Date().toISOString(),
                    claimedByUserId: null,
                    claimedByName: '',
                    claimedByUsername: '',
                    claimedAt: null
                });
                addedCount++;
            }

            if (addedCount === 0 && skippedDuplicates === 0) {
                return sendJson(res, 400, { error: 'يرجى إدخال كيي واحد على الأقل.' });
            }
            await saveState();
            return sendJson(res, 201, { ok: true, addedCount, skippedDuplicates, keys: state.vortexKeys });
        }

        if (pathname === '/api/admin/vortex' && method === 'DELETE') {
            const scope = String(searchParams.get('scope') || 'all');
            if (scope === 'available') {
                state.vortexKeys = state.vortexKeys.filter(k => k.status !== 'available');
            } else {
                state.vortexKeys = [];
            }
            await saveState();
            return sendJson(res, 200, { ok: true, keys: state.vortexKeys });
        }

        const vortexMatch = pathname.match(/^\/api\/admin\/vortex\/([^/]+)$/);
        if (vortexMatch && method === 'DELETE') {
            const id = decodeURIComponent(vortexMatch[1]);
            state.vortexKeys = state.vortexKeys.filter(k => k.id !== id);
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        // --- Admin Users Management (No plaintext passwords stored or returned) ---
        if (pathname === '/api/admin/users' && method === 'GET') {
            const now = Date.now();
            const users = state.users.map(u => {
                const userSubs = state.submissions.filter(s => s.userId === u.id);
                const userHwids = state.hwids.filter(h => h.userId === u.id);
                const activeSessions = state.sessions.filter(
                    s => s.role === 'user' && s.userId === u.id && s.expiresAt > now
                ).length;
                return {
                    id: u.id,
                    name: u.name,
                    username: u.username,
                    createdAt: u.createdAt,
                    lastLoginAt: u.lastLoginAt || null,
                    hasActiveSession: activeSessions > 0,
                    activeSessions,
                    submissionsCount: userSubs.length,
                    totalValid: userSubs.reduce((acc, s) => acc + (typeof s.valid === 'number' ? s.valid : 0), 0),
                    totalMailLocked: userSubs.reduce((acc, s) => acc + (typeof s.mailLocked === 'number' ? s.mailLocked : 0), 0),
                    lastSubmissionAt: userSubs[0] ? userSubs[0].createdAt : null,
                    lastSubmissionAr: userSubs[0] ? userSubs[0].timestampAr : '',
                    hwidsCount: userHwids.length
                };
            }).sort((a, b) => String(b.lastLoginAt || b.createdAt).localeCompare(String(a.lastLoginAt || a.createdAt)));
            return sendJson(res, 200, { users });
        }

        const userPassMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/password$/);
        if (userPassMatch && method === 'PATCH') {
            const id = decodeURIComponent(userPassMatch[1]);
            const body = await readJsonBody(req);
            const newPassword = String(body.password || '');
            if (newPassword.length < 4 || newPassword.length > 128) {
                return sendJson(res, 400, { error: 'كلمة المرور الجديدة يجب أن تكون 4 أحرف على الأقل.' });
            }
            const user = state.users.find(u => u.id === id);
            if (!user) return sendJson(res, 404, { error: 'المستخدم غير موجود.' });
            user.passwordHash = hashPassword(newPassword);
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        const userLogoutMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/logout$/);
        if (userLogoutMatch && method === 'POST') {
            const id = decodeURIComponent(userLogoutMatch[1]);
            state.sessions = state.sessions.filter(s => !(s.role === 'user' && s.userId === id));
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        const userDelMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (userDelMatch && method === 'DELETE') {
            const id = decodeURIComponent(userDelMatch[1]);
            state.users = state.users.filter(u => u.id !== id);
            state.sessions = state.sessions.filter(s => !(s.role === 'user' && s.userId === id));
            await saveState();
            return sendJson(res, 200, { ok: true });
        }

        if (pathname === '/api/admin/config' && method === 'GET') {
            return sendJson(res, 200, state.config);
        }

        if (pathname === '/api/admin/config' && method === 'PUT') {
            const body = await readJsonBody(req);
            const botToken = String(body.botToken || '').trim();
            const chatId = String(body.chatId || '').trim();
            if (!botToken || !chatId) {
                return sendJson(res, 400, { error: 'يرجى إدخال Bot Token و Chat ID.' });
            }
            state.config = { botToken, chatId };
            await saveState();
            return sendJson(res, 200, { ok: true, config: state.config });
        }
    }

    return sendJson(res, 404, { error: 'Not found' });
}

function createAppServer() {
    return http.createServer(async (req, res) => {
        try {
            const urlObj = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
            const pathname = urlObj.pathname;

            if (pathname.startsWith('/api/')) {
                await handleApi(req, res, pathname, urlObj.searchParams);
                return;
            }

            if ((pathname === '/health' || pathname === '/healthz') && req.method === 'GET') {
                return sendJson(res, 200, { ok: true });
            }

            if ((pathname === '/' || pathname === '/index.html') && req.method === 'GET') {
                res.writeHead(200, {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-store'
                });
                fs.createReadStream(INDEX_FILE).pipe(res);
                return;
            }

            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not found');
        } catch (err) {
            if (err && err.message === 'PAYLOAD_TOO_LARGE') {
                return sendJson(res, 413, { error: 'حجم الطلب كبير جداً.' });
            }
            if (err && err.message === 'INVALID_JSON') {
                return sendJson(res, 400, { error: 'تنسيق JSON غير صالح.' });
            }
            console.error('Server error:', err);
            sendJson(res, 500, { error: 'حدث خطأ داخلي في الخادم.' });
        }
    });
}

if (require.main === module) {
    const server = createAppServer();
    server.listen(PORT, HOST, () => {
        console.log(`READY: http://${HOST}:${PORT}`);
    });
}

module.exports = { createAppServer };
