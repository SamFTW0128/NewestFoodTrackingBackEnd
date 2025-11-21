// cottonwar-backend/server.js

// Simple Express + SQLite backend with JWT auth

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const db = new sqlite3.Database('./foodtrack.db');
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';

// ✅ IMPROVED CORS CONFIGURATION
app.use(cors({
  origin: '*', // Allow all origins (for development/testing)
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Add OPTIONS handler for preflight requests
app.options('*', cors());

app.use(express.json());


// Create tables if they don't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('customer','restaurant','rider','admin')),
      location TEXT,
      vehicle_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER,
      restaurant_id INTEGER,
      rider_id INTEGER,
      status TEXT CHECK (status IN ('pending','preparing','ready','picked_up','delivered','cancelled')),
      items TEXT,
      total REAL,
      delivery_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES users(id),
      FOREIGN KEY(restaurant_id) REFERENCES users(id),
      FOREIGN KEY(rider_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER,
      reviewer_id INTEGER,
      reviewee_id INTEGER,
      rating INTEGER CHECK (rating >= 1 AND rating <= 5),
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(order_id) REFERENCES orders(id),
      FOREIGN KEY(reviewer_id) REFERENCES users(id),
      FOREIGN KEY(reviewee_id) REFERENCES users(id)
    )
  `);
});

// Helper: create JWT token
function createToken(user) {
  const payload = {
    id: user.id,
    userId: user.user_id,
    name: user.name,
    role: user.role
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

// Auth middleware
function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = auth.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.post('/api/register', async (req, res) => {
  const { userId, name, password, role, location, vehicleType } = req.body;
  if (!userId || !name || !password || !role) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const hash = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users (user_id, name, password_hash, role, location, vehicle_type) VALUES (?,?,?,?,?,?)`,
    [userId, name, hash, role, location || null, vehicleType || null],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'User already exists or invalid data' });
      }
      const user = { id: this.lastID, user_id: userId, name, role };
      res.json({ token: createToken(user), user });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { userId, password } = req.body;
  db.get(`SELECT * FROM users WHERE user_id = ?`, [userId], async (err, row) => {
    if (err || !row) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = { id: row.id, user_id: row.user_id, name: row.name, role: row.role };
    res.json({ token: createToken(user), user });
  });
});

app.get('/api/orders', authRequired, (req, res) => {
  const { role, id } = req.user;
  let sql = `SELECT * FROM orders`;
  let params = [];
  if (role === 'customer') {
    sql += ` WHERE customer_id = ?`;
    params = [id];
  } else if (role === 'restaurant') {
    sql += ` WHERE restaurant_id = ?`;
    params = [id];
  } else if (role === 'rider') {
    sql += ` WHERE rider_id = ? OR rider_id IS NULL`;
    params = [id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows || []);
  });
});

app.post('/api/orders', authRequired, (req, res) => {
  const { restaurantId, items, total, deliveryAddress } = req.body;
  const customerId = req.user.id;
  db.run(
    `INSERT INTO orders (customer_id, restaurant_id, status, items, total, delivery_address) VALUES (?,?,?,?,?,?)`,
    [customerId, restaurantId, 'pending', JSON.stringify(items), total, deliveryAddress],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to create order' });
      res.json({ id: this.lastID, status: 'pending' });
    }
  );
});

app.patch('/api/orders/:id', authRequired, (req, res) => {
  const { status, riderId } = req.body;
  const orderId = req.params.id;
  let sql = `UPDATE orders SET status = ?`;
  let params = [status];
  if (riderId !== undefined) {
    sql += `, rider_id = ?`;
    params.push(riderId);
  }
  sql += ` WHERE id = ?`;
  params.push(orderId);
  db.run(sql, params, function (err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
