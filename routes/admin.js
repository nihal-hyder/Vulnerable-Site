const express = require('express');
const vulnState = require('../lib/vulnState');
const ftpControl = require('../lib/ftpControl');

const router = express.Router();

// Fixed demo credentials for the pentest control panel.
// Change these in lib/adminAuth or via ADMIN_PANEL_PASSWORD env var before
// exposing this app beyond your own machine.
const ADMIN_USER = process.env.ADMIN_PANEL_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PANEL_PASSWORD || 'admin123';

function requireAdmin(req, res, next) {
  if (req.session.isPentestAdmin) return next();
  res.redirect('/admin/login');
}

router.get('/login', (req, res) => {
  res.render('admin/login', { error: null });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isPentestAdmin = true;
    return res.redirect('/admin');
  }
  res.render('admin/login', { error: 'Incorrect username or password.' });
});

router.post('/logout', (req, res) => {
  req.session.isPentestAdmin = false;
  res.redirect('/admin/login');
});

router.get('/', requireAdmin, (req, res) => {
  res.render('admin/dashboard', {
    vulns: vulnState.getAll(),
    ftpOn: ftpControl.status(),
    ftpPort: ftpControl.FTP_PORT,
    message: req.query.msg || null
  });
});

router.post('/toggle', requireAdmin, (req, res) => {
  const { key, on } = req.body;
  try {
    vulnState.set(key, on === 'true' || on === '1');
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  if (req.headers['content-type'] && req.headers['content-type'].includes('json')) {
    return res.json({ ok: true, key, on: vulnState.isOn(key) });
  }
  res.redirect('/admin');
});

router.post('/set-all', requireAdmin, (req, res) => {
  vulnState.setAll(req.body.on === 'true' || req.body.on === '1');
  res.redirect('/admin?msg=' + encodeURIComponent(req.body.on === 'true' ? 'All vulnerabilities opened' : 'All vulnerabilities closed'));
});

router.get('/api/state', requireAdmin, (req, res) => {
  res.json({ vulns: vulnState.getAll(), ftpOn: ftpControl.status() });
});

module.exports = router;
