// run `node index.js` in the terminal

console.log(`Hello Node.js v${process.versions.node}!`);
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB
let db;
const client = new MongoClient(process.env.MONGODB_URI);

async function connectDB() {
  await client.connect();
  db = client.db('fuco-ai');
  await db.collection('users').createIndex({ username: 1 }, { unique: true });
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('emailRateLimit').createIndex({ email: 1 });
  await db.collection('aiAgents').createIndex({ role: 1 });
  await db.collection('aiAgents').createIndex({ group: 1 });
  await db.collection('teams').createIndex({ owner: 1 });
  await db.collection('chatHistory').createIndex({ agentId: 1 });
  console.log('Connected to MongoDB');
}

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'fuco-secret',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { maxAge: 2 * 24 * 60 * 60 * 1000 }
}));

// Email rate limit
const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => res.json({ ok: false, error: 'Bạn gửi quá nhiều yêu cầu. Vui lòng thử lại sau 1 giờ.' })
});

// Load user middleware
app.use(async (req, res, next) => {
  if (req.session && req.session.userId) {
    try {
      const user = await db.collection('users').findOne({ _id: new ObjectId(req.session.userId) });
      if (!user || user.locked) {
        req.session.destroy();
        return res.redirect('/login');
      }
      res.locals.user = user;
      req.user = user;
    } catch {
      req.session.destroy();
      return res.redirect('/login');
    }
  } else {
    res.locals.user = null;
    req.user = null;
  }
  next();
});

// Auth middleware
const requireLogin = (req, res, next) => {
  if (!req.user) return res.redirect('/login');
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') return res.redirect('/');
  next();
};

// Admin emails cứng
const ADMIN_EMAILS = ['cabien0789@gmail.com', 'tuannreal01@gmail.com'];

// Brevo send email
async function sendEmail(to, subject, html) {
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'api-key': process.env.BREVO_API_KEY
    },
    body: JSON.stringify({
      sender: { name: 'Fuco AI', email: process.env.GMAIL_USER },
      to: [{ email: to }],
      subject,
      htmlContent: html
    })
  });
  return res.ok;
}

// Email rate limit check (DB)
async function checkEmailRateLimit(email) {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const count = await db.collection('emailRateLimit').countDocuments({ email, sentAt: { $gte: oneHourAgo } });
  return count < 3;
}
async function recordEmailSent(email) {
  await db.collection('emailRateLimit').insertOne({ email, sentAt: new Date() });
}

// ==================== AUTH ====================

// GET /login
app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('login', { error: null });
});

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.collection('users').findOne({
      $or: [{ username }, { email: username }]
    });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.render('login', { error: 'Tên đăng nhập hoặc mật khẩu không đúng.' });
    }
    if (!user.verified) return res.render('login', { error: 'Tài khoản chưa được xác thực email.' });
    if (user.locked) return res.render('login', { error: 'Tài khoản đã bị khóa.' });
    req.session.userId = user._id.toString();
    res.redirect('/');
  } catch {
    res.render('login', { error: 'Có lỗi xảy ra, vui lòng thử lại.' });
  }
});

// GET /register
app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('register', { error: null });
});

// POST /register
app.post('/register', emailLimiter, async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (!username || !email || !password) return res.render('register', { error: 'Vui lòng điền đầy đủ thông tin.' });
    if (password.length < 6) return res.render('register', { error: 'Mật khẩu phải có ít nhất 6 ký tự.' });

    const existing = await db.collection('users').findOne({ $or: [{ username }, { email }] });
    if (existing) return res.render('register', { error: 'Tên đăng nhập hoặc email đã tồn tại.' });

    const canSend = await checkEmailRateLimit(email);
    if (!canSend) return res.render('register', { error: 'Email này đã được gửi quá nhiều lần. Vui lòng thử lại sau 1 giờ.' });

    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = Math.random().toString(36).substring(2, 8).toUpperCase();
    const isAdmin = ADMIN_EMAILS.includes(email);

    await db.collection('users').insertOne({
      username,
      email,
      password: hashed,
      role: isAdmin ? 'admin' : 'user',
      verified: false,
      verifyToken,
      locked: false,
      canCreateTeam: false,
      teamLimit: 0,
      createdAt: new Date()
    });

    await recordEmailSent(email);
    await sendEmail(email, 'Xác thực tài khoản Fuco AI', `
      <div style="background:#f0f4ff;padding:40px 0;font-family:sans-serif">
        <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#2563eb,#1d4ed8);padding:32px;text-align:center">
            <h1 style="color:#fff;margin:0;font-size:24px">Fuco AI</h1>
          </div>
          <div style="padding:32px">
            <h2 style="color:#1e293b;margin:0 0 16px">Xác thực tài khoản</h2>
            <p style="color:#64748b">Mã xác thực của bạn là:</p>
            <div style="background:#eff6ff;border:2px solid #2563eb;border-radius:8px;padding:20px;text-align:center;font-size:32px;font-weight:bold;color:#2563eb;letter-spacing:8px">${verifyToken}</div>
            <p style="color:#64748b;font-size:14px;margin-top:16px">Mã có hiệu lực trong 24 giờ.</p>
          </div>
        </div>
      </div>
    `);

    res.redirect(`/verify?email=${encodeURIComponent(email)}`);
  } catch (e) {
    if (e.code === 11000) return res.render('register', { error: 'Tên đăng nhập hoặc email đã tồn tại.' });
    res.render('register', { error: 'Có lỗi xảy ra, vui lòng thử lại.' });
  }
});

// GET /verify
app.get('/verify', (req, res) => {
  res.render('verify', { email: req.query.email || '', error: null });
});

// POST /verify
app.post('/verify', async (req, res) => {
  const { email, token } = req.body;
  try {
    const user = await db.collection('users').findOne({ email, verifyToken: token.toUpperCase() });
    if (!user) return res.render('verify', { email, error: 'Mã xác thực không đúng.' });
    await db.collection('users').updateOne({ _id: user._id }, { $set: { verified: true }, $unset: { verifyToken: '' } });
    res.redirect('/login');
  } catch {
    res.render('verify', { email, error: 'Có lỗi xảy ra, vui lòng thử lại.' });
  }
});

// GET /forgot-password
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null, success: null });
});

// POST /forgot-password
app.post('/forgot-password', emailLimiter, async (req, res) => {
  const { email } = req.body;
  try {
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.render('forgot-password', { error: null, success: 'Nếu email tồn tại, chúng tôi đã gửi mã đặt lại mật khẩu.' });

    const canSend = await checkEmailRateLimit(email);
    if (!canSend) return res.render('forgot-password', { error: 'Email này đã được gửi quá nhiều lần. Vui lòng thử lại sau 1 giờ.', success: null });

    const resetToken = Math.random().toString(36).substring(2, 8).toUpperCase();
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await db.collection('users').updateOne({ _id: user._id }, { $set: { resetToken, resetExpires } });
    await recordEmailSent(email);
    await sendEmail(email, 'Đặt lại mật khẩu Fuco AI', `
      <div style="background:#f0f4ff;padding:40px 0;font-family:sans-serif">
        <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden">
          <div style="background:linear-gradient(135deg,#2563eb,#1d4ed8);padding:32px;text-align:center">
            <h1 style="color:#fff;margin:0;font-size:24px">Fuco AI</h1>
          </div>
          <div style="padding:32px">
            <h2 style="color:#1e293b;margin:0 0 16px">Đặt lại mật khẩu</h2>
            <p style="color:#64748b">Mã đặt lại mật khẩu của bạn là:</p>
            <div style="background:#eff6ff;border:2px solid #2563eb;border-radius:8px;padding:20px;text-align:center;font-size:32px;font-weight:bold;color:#2563eb;letter-spacing:8px">${resetToken}</div>
            <p style="color:#64748b;font-size:14px;margin-top:16px">Mã có hiệu lực trong 1 giờ.</p>
          </div>
        </div>
      </div>
    `);
    res.render('forgot-password', { error: null, success: 'Mã đặt lại mật khẩu đã được gửi đến email của bạn.' });
  } catch {
    res.render('forgot-password', { error: 'Có lỗi xảy ra, vui lòng thử lại.', success: null });
  }
});

// GET /reset-password
app.get('/reset-password', (req, res) => {
  res.render('reset-password', { email: req.query.email || '', error: null });
});

// POST /reset-password
app.post('/reset-password', async (req, res) => {
  const { email, token, password } = req.body;
  try {
    const user = await db.collection('users').findOne({ email, resetToken: token.toUpperCase(), resetExpires: { $gt: new Date() } });
    if (!user) return res.render('reset-password', { email, error: 'Mã không đúng hoặc đã hết hạn.' });
    if (password.length < 6) return res.render('reset-password', { email, error: 'Mật khẩu phải có ít nhất 6 ký tự.' });
    const hashed = await bcrypt.hash(password, 10);
    await db.collection('users').updateOne({ _id: user._id }, { $set: { password: hashed }, $unset: { resetToken: '', resetExpires: '' } });
    res.redirect('/login');
  } catch {
    res.render('reset-password', { email, error: 'Có lỗi xảy ra, vui lòng thử lại.' });
  }
});

// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ==================== TRANG CHỦ ====================

// GET /
app.get('/', requireLogin, async (req, res) => {
  try {
    const [teams, agents] = await Promise.all([
      db.collection('teams').find({ owner: req.user.username }).toArray(),
      db.collection('aiAgents').find({ role: 'employee' }).toArray()
    ]);
    res.render('home', { teams, agents, totalAgents: agents.length });
  } catch {
    res.render('home', { teams: [], agents: [], totalAgents: 0 });
  }
});

// ==================== TEAM ====================

// GET /teams/create
app.get('/teams/create', requireLogin, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && !req.user.canCreateTeam) return res.redirect('/');
    const agents = await db.collection('aiAgents').find({ role: 'employee' }).toArray();
    const groups = ['Lập trình & Kỹ thuật', 'Viết lách & Nội dung', 'Phân tích & Nghiên cứu', 'Sáng tạo & Thiết kế', 'Trợ lý & Quản lý'];
    res.render('create-team', { agents, groups, error: null });
  } catch {
    res.redirect('/');
  }
});

// POST /teams/create
app.post('/teams/create', requireLogin, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && !req.user.canCreateTeam) return res.json({ ok: false, error: 'Bạn chưa được cấp quyền tạo team.' });

    const { name, memberIds, leaderId } = req.body;
    const ids = Array.isArray(memberIds) ? memberIds : [memberIds];

    if (req.user.role !== 'admin' && ids.length > 4) return res.json({ ok: false, error: 'Tối đa 4 AI trong một team.' });

    if (req.user.role !== 'admin') {
      const teamCount = await db.collection('teams').countDocuments({ owner: req.user.username });
      if (teamCount >= req.user.teamLimit) return res.json({ ok: false, error: `Bạn đã đạt giới hạn ${req.user.teamLimit} team.` });
    }

    if (!leaderId || !ids.includes(leaderId)) return res.json({ ok: false, error: 'Vui lòng chỉ định leader.' });

    const agents = await db.collection('aiAgents').find({ _id: { $in: ids.map(id => new ObjectId(id)) } }).toArray();
    const members = agents.map(a => ({
      agentId: a._id.toString(),
      name: a.name,
      platform: a.platform,
      group: a.group,
      isLeader: a._id.toString() === leaderId
    }));

    await db.collection('teams').insertOne({
      name,
      owner: req.user.username,
      members,
      createdAt: new Date()
    });

    res.json({ ok: true });
  } catch {
    res.json({ ok: false, error: 'Có lỗi xảy ra, vui lòng thử lại.' });
  }
});

// GET /teams/:id
app.get('/teams/:id', requireLogin, async (req, res) => {
  try {
    const team = await db.collection('teams').findOne({ _id: new ObjectId(req.params.id) });
    if (!team) return res.redirect('/');
    if (team.owner !== req.user.username && req.user.role !== 'admin') return res.redirect('/');
    res.render('team', { team });
  } catch {
    res.redirect('/');
  }
});

// DELETE /teams/:id
app.delete('/teams/:id', requireLogin, async (req, res) => {
  try {
    const team = await db.collection('teams').findOne({ _id: new ObjectId(req.params.id) });
    if (!team) return res.json({ ok: false });
    if (team.owner !== req.user.username && req.user.role !== 'admin') return res.json({ ok: false });
    await db.collection('teams').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// POST /teams/:id/chat — người dùng gửi yêu cầu cho team
app.post('/teams/:id/chat', requireLogin, async (req, res) => {
  try {
    const team = await db.collection('teams').findOne({ _id: new ObjectId(req.params.id) });
    if (!team) return res.json({ ok: false, error: 'Team không tồn tại.' });
    if (team.owner !== req.user.username && req.user.role !== 'admin') return res.json({ ok: false, error: 'Không có quyền.' });

    const { message } = req.body;
    const leader = team.members.find(m => m.isLeader);
    const members = team.members.filter(m => !m.isLeader);

    // Lấy thông tin agent leader
    const leaderAgent = await db.collection('aiAgents').findOne({ _id: new ObjectId(leader.agentId) });
    if (!leaderAgent) return res.json({ ok: false, error: 'Leader AI không tồn tại.' });

    // Leader đánh giá yêu cầu và phân công
    const leaderEval = await callAI(leaderAgent, `
Bạn là ${leaderAgent.name}, leader của team AI. Nhiệm vụ của bạn:
1. Đánh giá yêu cầu sau có khả thi không
2. Nếu khả thi, phân công nhiệm vụ cụ thể cho từng thành viên: ${members.map(m => m.name).join(', ')}
3. Nếu không khả thi, giải thích lý do

Yêu cầu: ${message}

Trả lời theo format:
ĐÁNH GIÁ: [khả thi/không khả thi]
LÝ DO: [nếu không khả thi]
PHÂN CÔNG:
- [tên thành viên]: [nhiệm vụ cụ thể]
    `);

    if (leaderEval.includes('không khả thi')) {
      return res.json({ ok: true, result: leaderEval });
    }

    // Các thành viên thực hiện nhiệm vụ song song
    const memberResults = await Promise.all(members.map(async (member) => {
      const memberAgent = await db.collection('aiAgents').findOne({ _id: new ObjectId(member.agentId) });
      if (!memberAgent) return { name: member.name, result: 'Agent không khả dụng.' };
      const result = await callAI(memberAgent, `
Bạn là ${memberAgent.name}, thành viên của team AI. 
Yêu cầu gốc của người dùng: ${message}
Nhiệm vụ của bạn (được leader phân công): ${extractTask(leaderEval, member.name)}
Hãy thực hiện nhiệm vụ và trả về kết quả chi tiết.
      `);
      return { name: member.name, result };
    }));

    // Leader tổng hợp kết quả
    const summary = await callAI(leaderAgent, `
Bạn là ${leaderAgent.name}, leader của team AI.
Yêu cầu gốc của người dùng: ${message}
Kết quả từ các thành viên:
${memberResults.map(r => `${r.name}: ${r.result}`).join('\n\n')}
Hãy tổng hợp thành một kết quả hoàn chỉnh, rõ ràng và hữu ích nhất cho người dùng.
    `);

    res.json({ ok: true, result: summary, details: memberResults });
  } catch {
    res.json({ ok: false, error: 'Có lỗi xảy ra.' });
  }
});

// Hàm gọi AI theo platform
async function callAI(agent, prompt) {
  try {
    if (agent.platform === 'Groq') {
      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${agent.apiKey}` },
        body: JSON.stringify({ model: agent.model || 'llama-3.3-70b-versatile', messages: [{ role: 'user', content: prompt }], max_tokens: 2000 })
      });
      const data = await res.json();
      return data.choices?.[0]?.message?.content || 'Không có phản hồi.';
    }
    if (agent.platform === 'Gemini') {
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${agent.model || 'gemini-2.0-flash'}:generateContent?key=${agent.apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
      });
      const data = await res.json();
      return data.candidates?.[0]?.content?.parts?.[0]?.text || 'Không có phản hồi.';
    }
    if (agent.platform === 'OpenRouter') {
      const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${agent.apiKey}` },
        body: JSON.stringify({ model: agent.model, messages: [{ role: 'user', content: prompt }], max_tokens: 2000 })
      });
      const data = await res.json();
      return data.choices?.[0]?.message?.content || 'Không có phản hồi.';
    }
    return 'Nền tảng không được hỗ trợ.';
  } catch {
    return 'Không thể kết nối AI.';
  }
}

function extractTask(leaderEval, memberName) {
  const lines = leaderEval.split('\n');
  const line = lines.find(l => l.includes(memberName));
  return line ? line.replace(`- ${memberName}:`, '').trim() : 'Hỗ trợ hoàn thành yêu cầu.';
}

// ==================== ADMIN ====================

// GET /admin
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const [users, agents, teams] = await Promise.all([
      db.collection('users').find({}).toArray(),
      db.collection('aiAgents').find({}).toArray(),
      db.collection('teams').find({}).toArray()
    ]);
    res.render('admin', { users, agents, teams });
  } catch {
    res.render('admin', { users: [], agents: [], teams: [] });
  }
});

// POST /admin/users/:id/toggle-lock
app.post('/admin/users/:id/toggle-lock', requireAdmin, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.json({ ok: false });
    await db.collection('users').updateOne({ _id: user._id }, { $set: { locked: !user.locked } });
    res.json({ ok: true, locked: !user.locked });
  } catch {
    res.json({ ok: false });
  }
});

// POST /admin/users/:id/toggle-team
app.post('/admin/users/:id/toggle-team', requireAdmin, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.json({ ok: false });
    await db.collection('users').updateOne({ _id: user._id }, { $set: { canCreateTeam: !user.canCreateTeam } });
    res.json({ ok: true, canCreateTeam: !user.canCreateTeam });
  } catch {
    res.json({ ok: false });
  }
});

// POST /admin/users/:id/set-team-limit
app.post('/admin/users/:id/set-team-limit', requireAdmin, async (req, res) => {
  try {
    const { limit } = req.body;
    await db.collection('users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { teamLimit: parseInt(limit) || 0 } });
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// POST /admin/agents — thêm AI nhân viên mới
app.post('/admin/agents', requireAdmin, async (req, res) => {
  try {
    const { platform, apiKey, model, group, description } = req.body;

    // Groq đặt tên bằng AI
    const nameAgent = { platform: 'Groq', apiKey: process.env.GROQ_API_KEY, model: 'llama-3.3-70b-versatile' };
    const name = await callAI(nameAgent, `Đặt một tên tiếng Anh ngắn gọn, sáng tạo và chuyên nghiệp cho một AI agent thuộc nhóm "${group}" với mô tả: "${description}". Chỉ trả về tên, không giải thích.`);

    await db.collection('aiAgents').insertOne({
      name: name.trim(),
      platform,
      apiKey,
      model,
      group,
      description,
      role: 'employee',
      status: 'active',
      addedAt: new Date()
    });
    res.json({ ok: true, name: name.trim() });
  } catch {
    res.json({ ok: false });
  }
});

// DELETE /admin/agents/:id
app.delete('/admin/agents/:id', requireAdmin, async (req, res) => {
  try {
    await db.collection('aiAgents').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// DELETE /admin/teams/:id
app.delete('/admin/teams/:id', requireAdmin, async (req, res) => {
  try {
    await db.collection('teams').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

// ==================== ADMIN CHAT VỚI AI QUẢN LÝ ====================

// GET /admin/council
app.get('/admin/council', requireAdmin, async (req, res) => {
  try {
    const [groqHistory, geminiHistory] = await Promise.all([
      db.collection('chatHistory').findOne({ agentId: 'groq-council' }),
      db.collection('chatHistory').findOne({ agentId: 'gemini-council' })
    ]);
    res.render('council', { groqHistory: groqHistory?.messages || [], geminiHistory: geminiHistory?.messages || [] });
  } catch {
    res.render('council', { groqHistory: [], geminiHistory: [] });
  }
});

// POST /admin/council/:agentId/chat
app.post('/admin/council/:agentId/chat', requireAdmin, async (req, res) => {
  try {
    const { agentId } = req.params;
    const { message } = req.body;

    const isGroq = agentId === 'groq-council';
    const agent = {
      platform: isGroq ? 'Groq' : 'Gemini',
      apiKey: isGroq ? process.env.GROQ_API_KEY : process.env.GEMINI_API_KEY,
      model: isGroq ? 'llama-3.3-70b-versatile' : 'gemini-2.0-flash',
      name: isGroq ? 'Groq' : 'Gemini'
    };

    const history = await db.collection('chatHistory').findOne({ agentId });
    const messages = history?.messages || [];

    const systemContext = isGroq
      ? 'Bạn là Groq, AI trinh sát nhân sự của hệ thống Fuco AI. Nhiệm vụ của bạn là tìm kiếm các AI có API miễn phí tiềm năng và báo cáo cho admin.'
      : 'Bạn là Gemini, AI nghiên cứu thị trường của hệ thống Fuco AI. Nhiệm vụ của bạn là báo cáo hướng phát triển cho trang web Fuco AI và xu hướng công nghệ AI.';

    const fullPrompt = `${systemContext}\n\nLịch sử trao đổi:\n${messages.map(m => `${m.role === 'user' ? 'Admin' : agent.name}: ${m.content}`).join('\n')}\n\nAdmin: ${message}`;
    const reply = await callAI(agent, fullPrompt);

    messages.push({ role: 'user', content: message, time: new Date() });
    messages.push({ role: 'assistant', content: reply, time: new Date() });

    await db.collection('chatHistory').updateOne(
      { agentId },
      { $set: { agentId, messages, updatedAt: new Date() } },
      { upsert: true }
    );

    res.json({ ok: true, reply });
  } catch {
    res.json({ ok: false, error: 'Có lỗi xảy ra.' });
  }
});

// ==================== DAILY JOBS ====================

// Kiểm tra AI quản lý mỗi ngày lúc 6 giờ sáng
async function dailyCouncilCheck() {
  try {
    // Kiểm tra Groq
    const groqOk = await testAI({ platform: 'Groq', apiKey: process.env.GROQ_API_KEY, model: 'llama-3.3-70b-versatile' });
    // Kiểm tra Gemini
    const geminiOk = await testAI({ platform: 'Gemini', apiKey: process.env.GEMINI_API_KEY, model: 'gemini-2.0-flash' });

    console.log(`[Daily Check] Groq: ${groqOk ? 'OK' : 'FAIL'} | Gemini: ${geminiOk ? 'OK' : 'FAIL'}`);
  } catch (e) {
    console.error('[Daily Check Error]', e);
  }
}

async function testAI(agent) {
  try {
    const result = await callAI(agent, 'Trả lời OK nếu bạn đang hoạt động.');
    return result && result.length > 0;
  } catch {
    return false;
  }
}

// Daily report từ 2 con AI quản lý
async function dailyReport() {
  try {
    const groqAgent = { platform: 'Groq', apiKey: process.env.GROQ_API_KEY, model: 'llama-3.3-70b-versatile', name: 'Groq' };
    const geminiAgent = { platform: 'Gemini', apiKey: process.env.GEMINI_API_KEY, model: 'gemini-2.0-flash', name: 'Gemini' };

    const today = new Date().toLocaleDateString('vi-VN');

    // Groq tìm AI mới
    const groqReport = await callAI(groqAgent, `Hôm nay ${today}, hãy tìm kiếm và liệt kê 5-10 AI platform có API miễn phí tiềm năng để kết nối vào hệ thống Fuco AI. Bao gồm: tên platform, model miễn phí, giới hạn token miễn phí, link đăng ký, đánh giá tiềm năng.`);

    // Gemini báo cáo thị trường
    const geminiReport = await callAI(geminiAgent, `Hôm nay ${today}, hãy báo cáo:\n1. HƯỚNG PHÁT TRIỂN TRANG WEB FUCO AI: 3-5 tính năng hoặc cải tiến nên làm tiếp theo\n2. XU HƯỚNG CÔNG NGHỆ AI: Những trend AI nổi bật hiện nay và ý tưởng ứng dụng vào web, app, sản phẩm công nghệ`);

    // Lưu báo cáo vào lịch sử chat
    const reportMessage = { role: 'assistant', content: groqReport, time: new Date(), isReport: true };
    const geminiReportMessage = { role: 'assistant', content: geminiReport, time: new Date(), isReport: true };

    await Promise.all([
      db.collection('chatHistory').updateOne(
        { agentId: 'groq-council' },
        { $push: { messages: reportMessage }, $set: { updatedAt: new Date() } },
        { upsert: true }
      ),
      db.collection('chatHistory').updateOne(
        { agentId: 'gemini-council' },
        { $push: { messages: geminiReportMessage }, $set: { updatedAt: new Date() } },
        { upsert: true }
      )
    ]);

    console.log('[Daily Report] Đã gửi báo cáo ngày', today);
  } catch (e) {
    console.error('[Daily Report Error]', e);
  }
}

// Xóa chat cũ và tổng hợp lúc 5:30 sáng mỗi ngày
async function dailySummaryAndClear() {
  try {
    const agents = ['groq-council', 'gemini-council'];
    const agentNames = { 'groq-council': 'Groq', 'gemini-council': 'Gemini' };
    const agentConfigs = {
      'groq-council': { platform: 'Groq', apiKey: process.env.GROQ_API_KEY, model: 'llama-3.3-70b-versatile' },
      'gemini-council': { platform: 'Gemini', apiKey: process.env.GEMINI_API_KEY, model: 'gemini-2.0-flash' }
    };

    for (const agentId of agents) {
      const history = await db.collection('chatHistory').findOne({ agentId });
      if (!history || !history.messages || history.messages.length === 0) continue;

      const oldMessages = history.messages.map(m => `${m.role === 'user' ? 'Admin' : agentNames[agentId]}: ${m.content}`).join('\n');
      const summary = await callAI(agentConfigs[agentId], `Tóm tắt những việc quan trọng chưa hoàn thành hoặc cần theo dõi từ lịch sử chat sau:\n\n${oldMessages}\n\nChỉ liệt kê những việc còn cần làm, bỏ qua những việc đã hoàn thành.`);

      await db.collection('chatHistory').updateOne(
        { agentId },
        { $set: { messages: [{ role: 'assistant', content: `📋 TỔNG HỢP VIỆC CÒN CẦN LÀM:\n\n${summary}`, time: new Date(), isSummary: true }], updatedAt: new Date() } }
      );
    }
    console.log('[Daily Summary] Đã tổng hợp và xóa chat cũ');
  } catch (e) {
    console.error('[Daily Summary Error]', e);
  }
}

// Scheduler đơn giản không dùng thư viện ngoài
function startScheduler() {
  setInterval(async () => {
    const now = new Date();
    const h = now.getHours();
    const m = now.getMinutes();
    if (h === 5 && m === 30) await dailySummaryAndClear();
    if (h === 6 && m === 0) { await dailyCouncilCheck(); await dailyReport(); }
  }, 60 * 1000);
}

// 404
app.use((req, res) => res.status(404).render('404'));

// Start
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Fuco AI running on port ${PORT}`);
    startScheduler();
  });
});