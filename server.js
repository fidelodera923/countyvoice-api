require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'countyvoice-dev-secret-change-me';

app.use(cors());
app.use(express.json({ limit: '3mb' }));

// ---------- MODELS ----------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  fullName: { type: String, default: '' },
  location: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  fullName: { type: String, default: 'County Admin' },
  createdAt: { type: Date, default: Date.now }
});

const issueSchema = new mongoose.Schema({
  ref: { type: String, unique: true },
  name: { type: String, default: 'Anonymous' },
  phone: { type: String, default: '' },
  ward: { type: String, required: true },
  category: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  photo: { type: String, default: null },
  priority: { type: String, enum: ['Low', 'Medium', 'High'], default: 'Medium' },
  department: { type: String, default: 'General' },
  status: {
    type: String,
    enum: ['Received', 'Under Review', 'Acknowledged', 'Funded', 'Ongoing', 'Rejected'],
    default: 'Received'
  },
  adminNotes: { type: String, default: '' },
  internalNotes: { type: String, default: '' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  history: [{
    status: String,
    date: { type: Date, default: Date.now },
    note: String
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const promiseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  sector: { type: String, required: true },
  budget: { type: String, default: 'Not specified' },
  year: { type: String, default: '2025/26' },
  status: { type: String, default: 'Not Started' },
  progress: { type: Number, default: 0 },
  notes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Issue = mongoose.model('Issue', issueSchema);
const PromiseModel = mongoose.model('Promise', promiseSchema);

const WARDS = [
  'Githunguri', 'Kiambu Town', 'Kikuyu', 'Limuru', 'Lari',
  'Kabete', 'Gatundu North', 'Gatundu South', 'Juja',
  'Thika Town', 'Ruiru', 'Other / Not listed'
];

const CATEGORIES = [
  'Roads & Transport', 'Water & Sanitation', 'Health', 'Education',
  'Security & Street Lighting', 'Agriculture & Markets',
  'Environment & Waste', 'Youth & Sports', 'Housing & Land', 'Other'
];

const DEPARTMENTS = [
  'General', 'Roads', 'Water', 'Health', 'Education', 'Security', 'Environment', 'Housing'
];

function makeRef() {
  return `CV-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Admin login required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired admin session. Please log in again.' });
  }
}

// Simple login rate limit (per IP)
const loginAttempts = new Map();
function checkLoginLimit(ip) {
  const now = Date.now();
  let list = (loginAttempts.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  if (list.length >= 20) {
    loginAttempts.set(ip, list);
    return false;
  }
  list.push(now);
  loginAttempts.set(ip, list);
  return true;
}

async function ensureSingleAdmin() {
  const count = await Admin.countDocuments();
  if (count > 0) return;
  const username = (process.env.ADMIN_USERNAME || 'admin').toLowerCase();
  const password = process.env.ADMIN_PASSWORD || 'Admin@123456';
  const fullName = process.env.ADMIN_FULLNAME || 'County Admin';
  const hash = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hash, fullName });
  console.log('Single admin account created:', username);
}

// ---------- ROUTES ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.get('/api/wards', (req, res) => res.json(WARDS));
app.get('/api/categories', (req, res) => res.json(CATEGORIES));
app.get('/api/departments', (req, res) => res.json(DEPARTMENTS));

app.get('/api/stats', async (req, res) => {
  try {
    const total = await Issue.countDocuments();
    const received = await Issue.countDocuments({ status: 'Received' });
    const funded = await Issue.countDocuments({ status: { $in: ['Funded', 'Ongoing'] } });
    const wards = await Issue.distinct('ward');
    res.json({ total, received, funded, wards: wards.length });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

app.post('/api/auth/user/register', async (req, res) => {
  try {
    const { username, password, fullName, location } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    if (username.trim().length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!location) return res.status(400).json({ error: 'Location (ward) is required' });

    const exists = await User.findOne({ username: username.toLowerCase().trim() });
    if (exists) return res.status(400).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: username.toLowerCase().trim(),
      password: hash,
      fullName: (fullName || username).trim(),
      location: location.trim()
    });

    const token = signToken({ role: 'user', id: user._id, username: user.username });
    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { id: user._id, username: user.username, fullName: user.fullName, location: user.location }
    });
  } catch (e) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/user/login', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (!checkLoginLimit(ip)) {
      return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

    const token = signToken({ role: 'user', id: user._id, username: user.username });
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, username: user.username, fullName: user.fullName, location: user.location }
    });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (!checkLoginLimit(ip)) {
      return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    const admin = await Admin.findOne({ username: username.toLowerCase().trim() });
    if (!admin) return res.status(401).json({ error: 'Invalid username or password' });

    const ok = await bcrypt.compare(password, admin.password);
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

    const token = signToken({ role: 'admin', id: admin._id, username: admin.username, fullName: admin.fullName });
    res.json({
      message: 'Login successful',
      token,
      admin: { id: admin._id, username: admin.username, fullName: admin.fullName }
    });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/issues', async (req, res) => {
  try {
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.ward) filter.ward = req.query.ward;
    if (req.query.category) filter.category = req.query.category;
    if (req.query.priority) filter.priority = req.query.priority;
    if (req.query.department) filter.department = req.query.department;

    const issues = await Issue.find(filter).sort({ createdAt: -1 });

    // Hide internal notes from public responses
    const cleaned = issues.map(i => {
      const obj = i.toObject();
      delete obj.internalNotes;
      return obj;
    });
    res.json(cleaned);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load issues' });
  }
});

// Admin sees internal notes too
app.get('/api/admin/issues', authAdmin, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.ward) filter.ward = req.query.ward;
    if (req.query.category) filter.category = req.query.category;
    if (req.query.priority) filter.priority = req.query.priority;
    if (req.query.department) filter.department = req.query.department;
    if (req.query.q) {
      filter.$or = [
        { title: new RegExp(req.query.q, 'i') },
        { ref: new RegExp(req.query.q, 'i') },
        { description: new RegExp(req.query.q, 'i') }
      ];
    }
    const issues = await Issue.find(filter).sort({ createdAt: -1 });
    res.json(issues);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load issues' });
  }
});

app.get('/api/admin/issues/export', authAdmin, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.ward) filter.ward = req.query.ward;
    if (req.query.category) filter.category = req.query.category;
    if (req.query.priority) filter.priority = req.query.priority;
    if (req.query.department) filter.department = req.query.department;

    const issues = await Issue.find(filter).sort({ createdAt: -1 });
    const header = [
      'Reference', 'Name', 'Phone', 'Ward', 'Category', 'Department', 'Priority',
      'Title', 'Description', 'Status', 'Official Response', 'Internal Notes', 'Created At', 'Updated At'
    ];
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    const rows = issues.map(i => [
      i.ref, i.name, i.phone, i.ward, i.category, i.department, i.priority,
      i.title, i.description, i.status, i.adminNotes, i.internalNotes, i.createdAt, i.updatedAt
    ].map(esc).join(','));
    const csv = [header.join(','), ...rows].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="countyvoice-issues.csv"');
    res.send(csv);
  } catch (e) {
    res.status(500).json({ error: 'Export failed' });
  }
});

app.post('/api/issues', async (req, res) => {
  try {
    const { name, phone, ward, category, title, description, userId, photo } = req.body;
    if (!ward || !category || !title || !description) {
      return res.status(400).json({ error: 'Ward, category, title and description are required' });
    }
    const t = String(title).trim();
    const d = String(description).trim();
    if (t.length < 10) return res.status(400).json({ error: 'Title must be at least 10 characters' });
    if (d.length < 30) return res.status(400).json({ error: 'Description must be at least 30 characters' });
    if (photo && String(photo).length > 2000000) {
      return res.status(400).json({ error: 'Photo is too large. Please use a smaller image (under ~1.5MB).' });
    }

    const issue = await Issue.create({
      ref: makeRef(),
      name: (name || 'Anonymous').trim(),
      phone: (phone || '').trim(),
      ward,
      category,
      title: t,
      description: d,
      photo: photo || null,
      userId: userId || null,
      status: 'Received',
      priority: 'Medium',
      department: 'General',
      history: [{ status: 'Received', date: new Date(), note: 'Issue submitted by citizen' }]
    });

    const obj = issue.toObject();
    delete obj.internalNotes;
    res.status(201).json(obj);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to submit issue' });
  }
});

app.put('/api/issues/:id', authAdmin, async (req, res) => {
  try {
    const issue = await Issue.findById(req.params.id);
    if (!issue) return res.status(404).json({ error: 'Issue not found' });

    const { status, adminNotes, internalNotes, priority, department } = req.body;
    const allowedStatus = ['Received', 'Under Review', 'Acknowledged', 'Funded', 'Ongoing', 'Rejected'];
    const allowedPriority = ['Low', 'Medium', 'High'];

    if (status && allowedStatus.includes(status) && status !== issue.status) {
      issue.history.push({
        status,
        date: new Date(),
        note: adminNotes || `Status changed to ${status}`
      });
      issue.status = status;
    }
    if (typeof adminNotes === 'string') issue.adminNotes = adminNotes.trim();
    if (typeof internalNotes === 'string') issue.internalNotes = internalNotes.trim();
    if (priority && allowedPriority.includes(priority)) issue.priority = priority;
    if (typeof department === 'string' && department.trim()) issue.department = department.trim();
    issue.updatedAt = new Date();
    await issue.save();
    res.json(issue);
  } catch (e) {
    res.status(500).json({ error: 'Failed to update issue' });
  }
});

app.get('/api/promises', async (req, res) => {
  try {
    const list = await PromiseModel.find().sort({ createdAt: -1 });
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load promises' });
  }
});

app.post('/api/promises', authAdmin, async (req, res) => {
  try {
    const { title, sector, budget, year, status, progress, notes } = req.body;
    if (!title || !sector) return res.status(400).json({ error: 'Title and sector are required' });
    const item = await PromiseModel.create({
      title: title.trim(),
      sector: sector.trim(),
      budget: budget || 'Not specified',
      year: year || '2025/26',
      status: status || 'Not Started',
      progress: Number(progress) || 0,
      notes: notes || ''
    });
    res.status(201).json(item);
  } catch (e) {
    res.status(500).json({ error: 'Failed to add promise' });
  }
});

async function start() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('Missing MONGODB_URI');
    process.exit(1);
  }
  await mongoose.connect(uri);
  console.log('Connected to MongoDB');
  await ensureSingleAdmin();
  app.listen(PORT, () => console.log(`CountyVoice API running on port ${PORT}`));
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});