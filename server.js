require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));

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
  status: {
    type: String,
    enum: ['Received', 'Under Review', 'Acknowledged', 'Funded', 'Ongoing', 'Rejected'],
    default: 'Received'
  },
  adminNotes: { type: String, default: '' },
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

function makeRef() {
  return `CV-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
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

// Citizen register
app.post('/api/auth/user/register', async (req, res) => {
  try {
    const { username, password, fullName, location } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    if (username.trim().length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!location) {
      return res.status(400).json({ error: 'Location (ward) is required' });
    }

    const exists = await User.findOne({ username: username.toLowerCase().trim() });
    if (exists) return res.status(400).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: username.toLowerCase().trim(),
      password: hash,
      fullName: (fullName || username).trim(),
      location: location.trim()
    });

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        location: user.location
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Citizen login
app.post('/api/auth/user/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ username: username.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        location: user.location
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin login ONLY (no public admin register)
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const admin = await Admin.findOne({ username: username.toLowerCase().trim() });
    if (!admin) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const ok = await bcrypt.compare(password, admin.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    res.json({
      message: 'Login successful',
      admin: {
        id: admin._id,
        username: admin.username,
        fullName: admin.fullName
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Issues list
app.get('/api/issues', async (req, res) => {
  try {
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    const issues = await Issue.find(filter).sort({ createdAt: -1 });
    res.json(issues);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load issues' });
  }
});

// Create issue
app.post('/api/issues', async (req, res) => {
  try {
    const { name, phone, ward, category, title, description, userId } = req.body;
    if (!ward || !category || !title || !description) {
      return res.status(400).json({ error: 'Ward, category, title and description are required' });
    }
    const t = String(title).trim();
    const d = String(description).trim();
    if (t.length < 10) return res.status(400).json({ error: 'Title must be at least 10 characters' });
    if (d.length < 30) return res.status(400).json({ error: 'Description must be at least 30 characters' });

    const issue = await Issue.create({
      ref: makeRef(),
      name: (name || 'Anonymous').trim(),
      phone: (phone || '').trim(),
      ward,
      category,
      title: t,
      description: d,
      userId: userId || null,
      status: 'Received',
      history: [{ status: 'Received', date: new Date(), note: 'Issue submitted by citizen' }]
    });

    res.status(201).json(issue);
  } catch (e) {
    res.status(500).json({ error: 'Failed to submit issue' });
  }
});

// Update issue (admin)
app.put('/api/issues/:id', async (req, res) => {
  try {
    const issue = await Issue.findById(req.params.id);
    if (!issue) return res.status(404).json({ error: 'Issue not found' });

    const { status, adminNotes } = req.body;
    const allowed = ['Received', 'Under Review', 'Acknowledged', 'Funded', 'Ongoing', 'Rejected'];

    if (status && allowed.includes(status) && status !== issue.status) {
      issue.history.push({
        status,
        date: new Date(),
        note: adminNotes || `Status changed to ${status}`
      });
      issue.status = status;
    }
    if (typeof adminNotes === 'string') issue.adminNotes = adminNotes.trim();
    issue.updatedAt = new Date();
    await issue.save();
    res.json(issue);
  } catch (e) {
    res.status(500).json({ error: 'Failed to update issue' });
  }
});

// Promises
app.get('/api/promises', async (req, res) => {
  try {
    const list = await PromiseModel.find().sort({ createdAt: -1 });
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load promises' });
  }
});

app.post('/api/promises', async (req, res) => {
  try {
    const { title, sector, budget, year, status, progress, notes } = req.body;
    if (!title || !sector) {
      return res.status(400).json({ error: 'Title and sector are required' });
    }
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

// ---------- START ----------
async function start() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('Missing MONGODB_URI');
    process.exit(1);
  }
  await mongoose.connect(uri);
  console.log('Connected to MongoDB');
  await ensureSingleAdmin();
  app.listen(PORT, () => {
    console.log(`CountyVoice API running on port ${PORT}`);
  });
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});