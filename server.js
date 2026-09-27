const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-this-secret';
const DATA_FILE = path.join(__dirname, 'data', 'customers.json');

app.use(cors());
app.use(express.json());

function readCustomers() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function writeCustomers(customers) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(customers, null, 2));
}

function publicCustomer(c) {
  const { passwordHash, ...safe } = c;
  return safe;
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'DruvaSolution API' });
});

// Temporary admin/setup endpoint for the first customer.
// Protect or remove this endpoint before production use.
app.post('/api/setup/customer', async (req, res) => {
  const { name, email, username, password } = req.body;
  if (!name || !email || !username || !password) {
    return res.status(400).json({ message: 'name, email, username and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  }

  const customers = readCustomers();
  const exists = customers.some(c => c.email.toLowerCase() === email.toLowerCase() || c.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ message: 'Email or username already exists.' });

  const customer = {
    id: Date.now().toString(),
    name,
    email,
    username,
    passwordHash: await bcrypt.hash(password, 12),
    active: true,
    software: 'Courier Billing Software',
    licenseKey: 'DEMO-' + Math.random().toString(36).slice(2, 10).toUpperCase(),
    expiryDate: '2027-12-31',
    createdAt: new Date().toISOString()
  };
  customers.push(customer);
  writeCustomers(customers);
  res.status(201).json({ customer: publicCustomer(customer) });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username/email and password are required.' });

  const customers = readCustomers();
  const customer = customers.find(c =>
    c.email.toLowerCase() === username.toLowerCase() || c.username.toLowerCase() === username.toLowerCase()
  );

  if (!customer || !customer.active || !(await bcrypt.compare(password, customer.passwordHash))) {
    return res.status(401).json({ message: 'Invalid username/email or password.' });
  }

  const token = jwt.sign({ customerId: customer.id }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, customer: publicCustomer(customer) });
});

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ message: 'Login required.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Session expired. Please login again.' });
  }
}

app.get('/api/me', auth, (req, res) => {
  const customer = readCustomers().find(c => c.id === req.user.customerId);
  if (!customer || !customer.active) return res.status(404).json({ message: 'Customer not found.' });
  res.json({ customer: publicCustomer(customer) });
});

app.listen(PORT, () => {
  console.log(`DruvaSolution API running at http://localhost:${PORT}`);
});
