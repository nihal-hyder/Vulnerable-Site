const express = require('express');
const session = require('express-session');
const path = require('path');
const cookieParser = require('cookie-parser');

const db = require('./lib/db');
const vulnState = require('./lib/vulnState');
const ftpControl = require('./lib/ftpControl');

const storeRoutes = require('./routes/store');
const adminRoutes = require('./routes/admin');

const PORT = process.env.PORT || 3000;

async function main() {
  await db.init();

  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(cookieParser());
  app.use(
    session({
      secret: 'northfield-demo-session-secret-not-for-production',
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 4 }
    })
  );

  app.use('/static', express.static(path.join(__dirname, 'public')));
  // Uploaded avatars are served from here. When insecure_upload is ON,
  // this directory intentionally allows script-bearing files through.
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

  // Make the current vuln map available to every view without passing it manually.
  app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    res.locals.cart = req.session.cart || [];
    next();
  });

  app.use('/', storeRoutes);
  app.use('/admin', adminRoutes);

  app.use((req, res) => {
    res.status(404).render('404', { path: req.path });
  });

  app.listen(PORT, () => {
    console.log('');
    console.log('  Northfield Supply Co. (deliberately vulnerable demo store)');
    console.log('  ---------------------------------------------------------');
    console.log(`  Storefront:   http://localhost:${PORT}/`);
    console.log(`  Pentest admin: http://localhost:${PORT}/admin`);
    console.log('');
  });

  // Start the FTP control module; it only actually opens a port when the
  // open_ftp vulnerability is toggled on (see lib/ftpControl.js).
  ftpControl.init();
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
