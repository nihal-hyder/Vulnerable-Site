const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const db = require('../lib/db');
const vulnState = require('../lib/vulnState');
const { escapeHtml, formatPrice, genToken } = require('../lib/util');

const router = express.Router();
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');
const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures');

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  next();
}

function getCsrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = genToken(32);
  return req.session.csrfToken;
}

// ---------- Home / catalog ----------

router.get('/', (req, res) => {
  const products = db.query('SELECT * FROM products ORDER BY id');
  res.render('home', { products, formatPrice, q: null });
});

router.get('/search', (req, res) => {
  const q = req.query.q || '';
  let products = [];
  let sqlError = null;

  if (vulnState.isOn('sql_injection')) {
    // VULNERABLE: user input concatenated directly into the SQL string.
    const sql = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%' OR category LIKE '%${q}%'`;
    try {
      products = db.rawQuery(sql);
    } catch (e) {
      sqlError = e.message; // verbose error, useful (and realistic) for error-based SQLi
    }
  } else {
    // SAFE: parameter-bound query.
    const like = `%${q}%`;
    products = db.query(
      'SELECT * FROM products WHERE name LIKE ? OR description LIKE ? OR category LIKE ?',
      [like, like, like]
    );
  }

  res.render('home', { products, formatPrice, q, sqlError });
});

router.get('/product/:id', (req, res) => {
  const product = db.query('SELECT * FROM products WHERE id = ?', [req.params.id])[0];
  if (!product) return res.status(404).render('404', { path: req.path });
  const reviews = db.query('SELECT * FROM reviews WHERE product_id = ? ORDER BY id DESC', [req.params.id]);
  res.render('product', {
    product,
    reviews,
    formatPrice,
    escapeHtml,
    xssOn: vulnState.isOn('stored_xss'),
    message: req.query.msg || null
  });
});

router.post('/product/:id/review', (req, res) => {
  const { author, body, rating } = req.body;
  const safeAuthor = escapeHtml(author || 'Anonymous').slice(0, 60);
  // The stored_xss toggle controls the product.ejs render step, not this
  // insert \u2014 we always store what was submitted (like a real app would),
  // the vulnerability is in how it's rendered back out.
  const cleanBody = vulnState.isOn('stored_xss') ? body : body; // stored as-is either way
  db.run('INSERT INTO reviews (product_id, author, body, rating) VALUES (?, ?, ?, ?)', [
    req.params.id,
    safeAuthor,
    cleanBody || '',
    Math.min(5, Math.max(1, parseInt(rating, 10) || 5))
  ]);
  res.redirect(`/product/${req.params.id}?msg=Review+posted`);
});

// ---------- Auth ----------

router.get('/login', (req, res) => {
  res.render('login', { error: null, next: req.query.next || '/' });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const next = req.body.next || '/';
  let user = null;

  if (vulnState.isOn('sql_injection')) {
    // VULNERABLE: both fields are concatenated straight into the query
    // string. Legitimate logins compare against the plaintext password
    // column (a legacy code path), so normal demo credentials still work
    // here too \u2014 but a crafted username such as  admin' --  comments out
    // the password check entirely and logs in as that user regardless of
    // what password was supplied. ' OR '1'='1 style payloads also work.
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password_plain = '${password}'`;
    try {
      const rows = db.rawQuery(sql);
      user = rows[0] || null;
    } catch (e) {
      return res.render('login', { error: 'Database error: ' + e.message, next });
    }
  } else {
    // SAFE: parameterized lookup + bcrypt compare.
    const rows = db.query('SELECT * FROM users WHERE username = ?', [username]);
    const candidate = rows[0];
    if (candidate && bcrypt.compareSync(password || '', candidate.password_hash)) {
      user = candidate;
    }
  }

  if (!user) {
    return res.render('login', { error: 'Invalid username or password.', next });
  }

  req.session.user = { id: user.id, username: user.username, email: user.email, is_admin: !!user.is_admin };
  res.redirect(next || '/');
});

router.get('/register', (req, res) => {
  res.render('register', { error: null });
});

router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) {
    return res.render('register', { error: 'Username and password are required.' });
  }
  const existing = db.query('SELECT id FROM users WHERE username = ?', [username]);
  if (existing.length) {
    return res.render('register', { error: 'That username is already taken.' });
  }
  const hash = bcrypt.hashSync(password, 8);
  db.run('INSERT INTO users (username, password_hash, password_plain, email) VALUES (?, ?, ?, ?)', [
    username,
    hash,
    password,
    email || ''
  ]);
  const user = db.query('SELECT * FROM users WHERE username = ?', [username])[0];
  req.session.user = { id: user.id, username: user.username, email: user.email, is_admin: false };
  res.redirect('/');
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ---------- Cart (simple, session-based, not a vuln surface) ----------

router.post('/cart/add', (req, res) => {
  const product = db.query('SELECT * FROM products WHERE id = ?', [req.body.productId])[0];
  if (!product) return res.redirect('/');
  const cart = req.session.cart || [];
  const existing = cart.find((i) => i.productId === product.id);
  if (existing) existing.qty += 1;
  else cart.push({ productId: product.id, name: product.name, price_cents: product.price_cents, qty: 1 });
  req.session.cart = cart;
  res.redirect(req.get('Referrer') || `/product/${product.id}`);
});

router.post('/cart/remove', (req, res) => {
  const cart = (req.session.cart || []).filter((i) => i.productId !== parseInt(req.body.productId, 10));
  req.session.cart = cart;
  res.redirect('/cart');
});

router.get('/cart', (req, res) => {
  const cart = req.session.cart || [];
  const total = cart.reduce((sum, i) => sum + i.price_cents * i.qty, 0);
  res.render('cart', { cart, total, formatPrice });
});

router.post('/checkout', requireLogin, (req, res) => {
  const cart = req.session.cart || [];
  if (!cart.length) return res.redirect('/cart');
  const total = cart.reduce((sum, i) => sum + i.price_cents * i.qty, 0);
  db.run('INSERT INTO orders (user_id, items_json, total_cents, status) VALUES (?, ?, ?, ?)', [
    req.session.user.id,
    JSON.stringify(cart),
    total,
    'Processing'
  ]);
  req.session.cart = [];
  res.render('checkout', { total, formatPrice });
});

// ---------- Account / orders (IDOR target) ----------

router.get('/account', requireLogin, (req, res) => {
  const orders = db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC', [req.session.user.id]);
  res.render('account', {
    orders,
    formatPrice,
    csrfToken: getCsrfToken(req),
    csrfOn: vulnState.isOn('csrf'),
    message: req.query.msg || null
  });
});

router.get('/account/orders/:id', requireLogin, (req, res) => {
  const order = db.query('SELECT * FROM orders WHERE id = ?', [req.params.id])[0];
  if (!order) return res.status(404).render('404', { path: req.path });

  if (!vulnState.isOn('idor')) {
    // SAFE: verify the order actually belongs to the logged-in user.
    if (order.user_id !== req.session.user.id) {
      return res.status(403).render('403', { reason: 'This order does not belong to your account.' });
    }
  }
  // VULNERABLE path (idor ON): no ownership check \u2014 any logged-in user
  // can view any order by guessing/incrementing the numeric ID.

  const owner = db.query('SELECT username FROM users WHERE id = ?', [order.user_id])[0];
  res.render('order', { order, owner, items: JSON.parse(order.items_json), formatPrice });
});

router.post('/account/email', requireLogin, (req, res) => {
  const { email, _csrf } = req.body;

  if (vulnState.isOn('csrf')) {
    // VULNERABLE: no token check at all \u2014 any origin can submit this form
    // on behalf of a logged-in victim.
  } else {
    // SAFE: validate the per-session anti-CSRF token.
    if (!_csrf || _csrf !== req.session.csrfToken) {
      return res.status(403).render('403', { reason: 'Missing or invalid CSRF token.' });
    }
  }

  if (email) {
    db.run('UPDATE users SET email = ? WHERE id = ?', [email, req.session.user.id]);
    req.session.user.email = email;
  }
  res.redirect('/account?msg=Email+updated');
});

// ---------- Avatar upload (insecure upload target) ----------

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    if (vulnState.isOn('insecure_upload')) {
      // VULNERABLE: trust the client-supplied filename/extension as-is.
      const safeName = `${Date.now()}-${file.originalname}`.replace(/[\/\\]/g, '_');
      cb(null, safeName);
    } else {
      // SAFE: ignore the original name/extension; derive a safe one from
      // the sniffed mimetype only.
      const extMap = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif' };
      const ext = extMap[file.mimetype] || '.bin';
      cb(null, `${Date.now()}-${genToken(8)}${ext}`);
    }
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (vulnState.isOn('insecure_upload')) {
      return cb(null, true); // VULNERABLE: anything goes, including .html/.svg/.php
    }
    const allowed = ['image/png', 'image/jpeg', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Only PNG, JPG, or GIF images are allowed.'));
    }
    cb(null, true);
  }
});

router.post('/account/avatar', requireLogin, (req, res) => {
  upload.single('avatar')(req, res, (err) => {
    if (err) return res.render('account', {
      orders: db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC', [req.session.user.id]),
      formatPrice,
      csrfToken: getCsrfToken(req),
      csrfOn: vulnState.isOn('csrf'),
      message: null,
      uploadError: err.message
    });
    if (req.file) {
      db.run('UPDATE users SET avatar = ? WHERE id = ?', [req.file.filename, req.session.user.id]);
      req.session.user.avatar = req.file.filename;
    }
    res.redirect('/account?msg=Avatar+updated');
  });
});

// Custom uploads handler: always sandboxes the filename to the uploads dir
// (so the demo app itself stays safe to run), but only applies real
// content-type / download protections when insecure_upload is OFF.
router.get('/uploads/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const full = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(full)) return res.status(404).render('404', { path: req.path });

  if (vulnState.isOn('insecure_upload')) {
    // VULNERABLE: served inline, content-type trusted from the extension,
    // so an uploaded .html/.svg can execute script when opened directly.
    return res.sendFile(full);
  }
  // SAFE: force a download, never render as the browser's own HTML/SVG.
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.sendFile(full);
});

// ---------- Sensitive data exposure ----------

router.get('/.env', (req, res) => {
  if (!vulnState.isOn('sensitive_data_exposure')) return res.status(404).render('404', { path: req.path });
  res.type('text/plain').sendFile(path.join(FIXTURES_DIR, 'env.demo'));
});

router.get('/backup.zip', (req, res) => {
  if (!vulnState.isOn('sensitive_data_exposure')) return res.status(404).render('404', { path: req.path });
  res.download(path.join(FIXTURES_DIR, 'backup.zip'), 'backup.zip');
});

module.exports = router;
