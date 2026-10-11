const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');

let SQL = null;
let db = null;

const DB_FILE = path.join(__dirname, '..', 'data', 'store.sqlite');

async function init() {
  SQL = await initSqlJs({
    locateFile: (file) => path.join(__dirname, '..', 'node_modules', 'sql.js', 'dist', file)
  });

  if (fs.existsSync(DB_FILE)) {
    const fileBuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
    seed();
    persist();
  }
}

function persist() {
  const data = db.export();
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, Buffer.from(data));
}

function seed() {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      password_plain TEXT,
      email TEXT,
      is_admin INTEGER DEFAULT 0,
      avatar TEXT DEFAULT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      tagline TEXT,
      description TEXT,
      price_cents INTEGER,
      category TEXT,
      badge TEXT,
      hue TEXT
    );

    CREATE TABLE reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      author TEXT,
      body TEXT,
      rating INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      items_json TEXT,
      total_cents INTEGER,
      status TEXT DEFAULT 'Processing',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const demoHash = bcrypt.hashSync('trailblazer', 8);
  const adminHash = bcrypt.hashSync('S0uthRidge!2024', 8);

  // NOTE: password_plain is a deliberate simplification so the
  // "sql_injection" vulnerable code path (which compares passwords as raw
  // SQL string literals rather than bcrypt-comparing them) can still be
  // demoed with working legitimate logins, not just the auth-bypass trick.
  // The "safe" login path never reads this column \u2014 it always uses
  // password_hash with bcrypt.compareSync.
  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, password_plain, email, is_admin) VALUES (?, ?, ?, ?, ?)'
  );
  insertUser.run(['demo', demoHash, 'trailblazer', 'demo@example.com', 0]);
  insertUser.run(['junebug', bcrypt.hashSync('pinecone88', 8), 'pinecone88', 'june@example.com', 0]);
  insertUser.run(['storeadmin', adminHash, 'S0uthRidge!2024', 'ops@northfieldsupply.test', 1]);
  insertUser.free();

  const products = [
    ['Contour 38 Backpack', 'Carries a week, weighs like a weekend.', 'A 38-liter trail pack with a suspended mesh back panel, hip-belt pockets sized for a real hand, and a roll-top that actually rolls flat. Built from 420D recycled ripstop.', 18900, 'Packs', 'Bestseller', 'moss'],
    ['Drift Quilt 20\u00b0', 'Sleeps warm, packs to a loaf of bread.', 'An 800-fill quilt rated to 20\u00b0F / -6\u00b0C with a differential cut that keeps down from migrating. No zippers, no bulk \u2014 just a cinch footbox and two webbing straps.', 24500, 'Sleep', 'New', 'rust'],
    ['Flintline Stove', 'Boils 500ml in under three minutes.', 'A titanium windscreen-integrated canister stove, 74 grams, with a piezo igniter rated for 15,000 clicks. Folds flatter than a pack of cards.', 6900, 'Cook', null, 'ink'],
    ['Lowline Bivy', 'A roof for one, rolled up small.', '15-denier silicone-coated nylon with a mesh face panel and a single hoop pole. Pitches on gravel, sand, or a granite slab in under 90 seconds.', 14200, 'Shelter', null, 'moss'],
    ['Switchback Poles (pair)', 'Carbon swing weight, aluminum durability.', 'A carbon-wrapped aluminum core pole with a flick-lock that holds under real load. Cork grips extend low for traversing side-hill.', 8900, 'Hike', null, 'rust'],
    ['Basin Water Filter', '1500 liters before the first backwash.', 'A hollow-fiber filter rated to 0.1 micron, gravity or squeeze compatible, with a backflush syringe included. Clears Giardia and Cryptosporidium.', 4500, 'Water', 'Bestseller', 'ink'],
    ['Talus Softshell', 'Breathes on the climb, blocks on the ridge.', 'A brushed-grid softshell with a DWR finish, articulated elbows, and a single chest pocket sized for a folded map or a phone.', 16500, 'Apparel', null, 'moss'],
    ['Ember Headlamp 400', '400 lumens, 38 grams, one dial.', 'A single-dial headlamp with a true red night mode and a rear battery pack for balance. USB-C rechargeable, runs 40 hours on low.', 5200, 'Gear', 'New', 'rust']
  ];
  const insertProduct = db.prepare(
    'INSERT INTO products (name, tagline, description, price_cents, category, badge, hue) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  for (const p of products) insertProduct.run(p);
  insertProduct.free();

  const reviews = [
    [1, 'ridgewalker', 'Carried this for 9 days on the Colorado Trail. Hip belt pockets fit my phone exactly, no chafing even loaded to 30lbs.', 5],
    [1, 'maria_k', 'Good pack but the roll-top is fiddly in the rain with gloves on.', 4],
    [3, 'altitude_tom', 'Boiled water at 11,000ft without a hiccup. Piezo igniter still working after a full season.', 5],
    [6, 'desert_dana', 'Flow rate held up even with silty water. Backflush syringe is a nice touch.', 5]
  ];
  const insertReview = db.prepare(
    'INSERT INTO reviews (product_id, author, body, rating) VALUES (?, ?, ?, ?)'
  );
  for (const r of reviews) insertReview.run(r);
  insertReview.free();

  const order1Items = JSON.stringify([
    { productId: 1, name: 'Contour 38 Backpack', qty: 1, price_cents: 18900 }
  ]);
  const order2Items = JSON.stringify([
    { productId: 3, name: 'Flintline Stove', qty: 1, price_cents: 6900 },
    { productId: 6, name: 'Basin Water Filter', qty: 1, price_cents: 4500 }
  ]);
  const order3Items = JSON.stringify([
    { productId: 2, name: 'Drift Quilt 20\u00b0', qty: 1, price_cents: 24500 }
  ]);
  const insertOrder = db.prepare(
    'INSERT INTO orders (user_id, items_json, total_cents, status) VALUES (?, ?, ?, ?)'
  );
  insertOrder.run([1, order1Items, 18900, 'Delivered']);
  insertOrder.run([1, order2Items, 11400, 'Shipped']);
  insertOrder.run([2, order3Items, 24500, 'Processing']);
  insertOrder.free();
}

// --- Raw/unsafe query path: builds SQL by string concatenation (SQL injection) ---
function rawQuery(sql) {
  try {
    const res = db.exec(sql);
    if (!res[0]) return [];
    const { columns, values } = res[0];
    return values.map((row) => {
      const obj = {};
      columns.forEach((col, i) => (obj[col] = row[i]));
      return obj;
    });
  } catch (e) {
    // Real SQL engines surface syntax errors to the caller; the vulnerable
    // code path intentionally lets that error bubble up as it would in a
    // real broken application (useful for error-based injection testing).
    throw e;
  }
}

// --- Safe path: always parameter-bound ---
function query(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.run(params);
  stmt.free();
  persist();
}

module.exports = { init, rawQuery, query, run, persist };
