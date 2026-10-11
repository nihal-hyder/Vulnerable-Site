const path = require('path');
const fs = require('fs');
const FtpSrv = require('ftp-srv');
const vulnState = require('./vulnState');

const FTP_PORT = process.env.FTP_PORT || 2121;
const FTP_ROOT = path.join(__dirname, '..', 'ftp-root');

let server = null;
let starting = false;

function ensureFixtureFiles() {
  fs.mkdirSync(path.join(FTP_ROOT, 'public'), { recursive: true });
  fs.mkdirSync(path.join(FTP_ROOT, 'backups'), { recursive: true });
  const readme = path.join(FTP_ROOT, 'public', 'welcome.txt');
  if (!fs.existsSync(readme)) {
    fs.writeFileSync(
      readme,
      'Northfield Supply Co. file drop\r\n' +
        'This anonymous FTP service is a deliberately exposed demo fixture.\r\n'
    );
  }
  const backup = path.join(FTP_ROOT, 'backups', 'store-backup-2024-03-01.sql');
  if (!fs.existsSync(backup)) {
    fs.writeFileSync(
      backup,
      '-- demo backup fixture, not a real database dump --\n' +
        "INSERT INTO users (username, password_hash) VALUES ('storeadmin', '$2a$08$demoFixtureHashOnly');\n"
    );
  }
}

async function start() {
  if (server || starting) return;
  starting = true;
  ensureFixtureFiles();

  server = new FtpSrv({
    url: `ftp://0.0.0.0:${FTP_PORT}`,
    anonymous: true,
    pasv_url: '127.0.0.1',
    greeting: ['Welcome to Northfield Supply Co. FTP (demo fixture \u2014 anonymous access enabled)']
  });

  server.on('login', ({ connection, username }, resolve, reject) => {
    // Anonymous login accepted for ANY username/password \u2014 this is the vulnerability.
    resolve({ root: FTP_ROOT });
  });

  server.on('client-error', () => {
    /* swallow noisy client errors from scanners in demo mode */
  });

  try {
    await server.listen();
    starting = false;
    console.log(`  [ftp] anonymous FTP service OPEN on ftp://127.0.0.1:${FTP_PORT}`);
  } catch (e) {
    starting = false;
    server = null;
    console.error('  [ftp] failed to start:', e.message);
  }
}

async function stop() {
  if (!server) return;
  try {
    await server.close();
  } catch (e) {
    // ignore
  }
  server = null;
  console.log('  [ftp] service CLOSED');
}

function status() {
  return !!server;
}

function init() {
  if (vulnState.isOn('open_ftp')) start();
  vulnState.onChange((key, on) => {
    if (key === 'open_ftp' || key === '*') {
      if (vulnState.isOn('open_ftp')) start();
      else stop();
    }
  });
}

module.exports = { init, start, stop, status, FTP_PORT };
