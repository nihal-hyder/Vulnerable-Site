const fs = require('fs');
const path = require('path');

const STATE_FILE = path.join(__dirname, '..', 'data', 'vuln-state.json');

const DEFINITIONS = {
  sql_injection: {
    name: 'SQL Injection',
    category: 'Injection',
    severity: 'Critical',
    cwe: 'CWE-89',
    location: 'POST /login, GET /search?q=',
    description:
      'Login and product search build SQL statements by concatenating user input directly into the query string instead of using parameters.',
    vulnerableHint: "Try username  ' OR '1'='1  with any password on /login, or  ' UNION SELECT ...  on the search box.",
    fixedBehavior: 'Both endpoints use parameter-bound queries, so input is always treated as data, never as SQL.'
  },
  stored_xss: {
    name: 'Stored Cross-Site Scripting (XSS)',
    category: 'Injection',
    severity: 'High',
    cwe: 'CWE-79',
    location: 'POST /product/:id/review (rendered on GET /product/:id)',
    description:
      'Product reviews are rendered back to every visitor without HTML-escaping, so a review body can contain live markup and script.',
    vulnerableHint: 'Post a review containing <script>alert(document.cookie)</script> and reload the product page.',
    fixedBehavior: 'Review text is HTML-escaped on render, so markup is shown as inert text.'
  },
  idor: {
    name: 'Insecure Direct Object Reference (IDOR)',
    category: 'Broken Access Control',
    severity: 'High',
    cwe: 'CWE-639',
    location: 'GET /account/orders/:id',
    description:
      "Order detail pages are looked up only by the numeric ID in the URL, with no check that the order belongs to the logged-in user.",
    vulnerableHint: 'Log in as any demo user, place an order, then increment/decrement the order ID in the URL to view other customers\u2019 orders.',
    fixedBehavior: 'The order is loaded and its owner is compared against the session user before rendering; mismatches return 403.'
  },
  insecure_upload: {
    name: 'Insecure / Unrestricted File Upload',
    category: 'Broken Access Control',
    severity: 'Critical',
    cwe: 'CWE-434',
    location: 'POST /account/avatar',
    description:
      'The avatar upload accepts any file extension and content type and serves uploaded files back from a public, script-enabled path.',
    vulnerableHint: 'Upload an .html or .svg file containing a <script> tag as your "avatar", then open the returned file URL directly.',
    fixedBehavior: 'Only .png/.jpg/.jpeg/.gif files under 2MB are accepted, content is sniffed (not trusted from the extension alone), and files are served with a forced download / no-script header.'
  },
  csrf: {
    name: 'Cross-Site Request Forgery (CSRF)',
    category: 'Broken Access Control',
    severity: 'Medium',
    cwe: 'CWE-352',
    location: 'POST /account/email',
    description:
      'The "change account email" form accepts a plain POST with no per-session anti-CSRF token, so any site can submit it on a logged-in victim\u2019s behalf.',
    vulnerableHint: 'Build an auto-submitting HTML form on another origin that POSTs a new email to /account/email while a victim session cookie is active.',
    fixedBehavior: 'The form includes a per-session CSRF token that is validated server-side before the email is changed.'
  },
  sensitive_data_exposure: {
    name: 'Sensitive Data Exposure',
    category: 'Security Misconfiguration',
    severity: 'High',
    cwe: 'CWE-200',
    location: 'GET /.env , GET /backup.zip',
    description:
      'Backup and environment files are left reachable under the web root, leaking database credentials and API keys.',
    vulnerableHint: 'Request /.env or /backup.zip directly \u2014 no authentication required.',
    fixedBehavior: 'Both paths return 404 and the files are not served from any public directory.'
  },
  open_ftp: {
    name: 'Open / Anonymous FTP Service',
    category: 'Security Misconfiguration',
    severity: 'High',
    cwe: 'CWE-284',
    location: 'FTP service on ftp://127.0.0.1:2121',
    description:
      'A real FTP service is started alongside the web app and accepts anonymous login with read/write access to a folder that mirrors site backups.',
    vulnerableHint: 'ftp 127.0.0.1 2121 then log in as user "anonymous" with any password.',
    fixedBehavior: 'The FTP service is stopped entirely \u2014 the port is closed.'
  }
};

function defaultState() {
  const state = {};
  for (const key of Object.keys(DEFINITIONS)) state[key] = true; // vulnerable by default
  return state;
}

function load() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return { ...defaultState(), ...parsed };
  } catch (e) {
    const state = defaultState();
    save(state);
    return state;
  }
}

function save(state) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

let current = load();
const listeners = [];

function isOn(key) {
  return !!current[key];
}

function getAll() {
  return Object.keys(DEFINITIONS).map((key) => ({
    key,
    on: isOn(key),
    ...DEFINITIONS[key]
  }));
}

function set(key, on) {
  if (!(key in DEFINITIONS)) throw new Error('Unknown vulnerability key: ' + key);
  current[key] = !!on;
  save(current);
  listeners.forEach((fn) => fn(key, current[key]));
  return current[key];
}

function setAll(on) {
  for (const key of Object.keys(DEFINITIONS)) current[key] = !!on;
  save(current);
  listeners.forEach((fn) => fn('*', on));
}

function onChange(fn) {
  listeners.push(fn);
}

module.exports = { DEFINITIONS, isOn, getAll, set, setAll, onChange };
