require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const express = require("express");
const path = require("path");
const multer = require("multer");
const db = require("better-sqlite3")("Mixue.db");
db.pragma("journal_mode = WAL");
const app = express();

// Setup database (tambahkan kolom role di users)
const createTables = db.transaction(() => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      is_featured INTEGER DEFAULT 0,
      image_url TEXT,
      description TEXT,
      stock INTEGER DEFAULT 1
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS carts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product_id INTEGER,
      quantity INTEGER DEFAULT 1,
      selected INTEGER DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(product_id) REFERENCES products(id)
    )
  `).run();

  db.prepare(`
    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY,
      full_name TEXT,
      phone TEXT,
      address TEXT,
      profile_image TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `).run();
});
createTables();

function getUserProfile(userId) {
  return db.prepare("SELECT * FROM user_profiles WHERE user_id = ?").get(userId);
}

function getCartItemCount(userId) {
  const row = db.prepare("SELECT SUM(quantity) as count FROM carts WHERE user_id = ?").get(userId);
  return row.count || 0;
}

// app config
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Serve folder uploads agar foto profile bisa diakses via browser
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cookieParser());
app.use(express.json());

// Setup multer untuk upload foto profil
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, req.user.userid + '_' + Date.now() + ext);
  }
});
const upload = multer({ storage });

// Middleware untuk decode JWT dan set req.user
app.use((req, res, next) => {
  res.locals.errors = [];
  try {
    const token = req.cookies.mixueforlife;
    if (!token) throw new Error("No token");
    const decoded = jwt.verify(token, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }
  res.locals.user = req.user;
  next();
});

// Middleware cek login
function mustBeLoggedin(req, res, next) {
  if (req.user) return next();
  return res.redirect("/loginuser");
}

// Middleware cek admin
function mustBeAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).send('Akses ditolak: hanya admin yang boleh masuk.');
}

// Validasi email simple dengan regex
function isValidEmail(email) {
  // Simple regex untuk email valid, bukan hanya alphanumeric
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ROUTES

app.get("/", (req, res) => res.redirect("/loginuser"));

app.get("/loginuser", (req, res) => res.render("loginuser", { errors: [] }));

app.post("/loginuser", (req, res) => {
  const errors = [];
  const { email = '', password = '' } = req.body;

  if (!email.trim()) errors.push("Email wajib diisi");
  else if (!isValidEmail(email)) errors.push("Format email tidak valid");
  if (!password) errors.push("Password wajib diisi");

  if (errors.length) return res.render("loginuser", { errors });

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    errors.push("Email atau password salah");
    return res.render("loginuser", { errors });
  }

  const token = jwt.sign({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    userid: user.id,
    email: user.email,
    role: user.role
  }, process.env.JWTSECRET);

  res.cookie("mixueforlife", token, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  });

  res.redirect(user.role === 'admin' ? "/admin" : "/index");
});

app.get("/daftar", (req, res) => res.render("daftar", { errors: [] }));

app.post("/daftar", (req, res) => {
  const errors = [];
  const { email = '', password = '' } = req.body;

  if (!email.trim()) errors.push("Email wajib diisi");
  else if (!isValidEmail(email)) errors.push("Format email tidak valid");
  if (!password) errors.push("Password wajib diisi");
  if (password.length < 12) errors.push("Password minimal 12 karakter");
  if (password.length > 70) errors.push("Password terlalu panjang");

  if (errors.length) return res.render("daftar", { errors });

  const hashed = bcrypt.hashSync(password, 10);

  try {
    const result = db.prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)").run(email, hashed, 'user');
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    const token = jwt.sign({
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      userid: user.id,
      email: user.email,
      role: user.role
    }, process.env.JWTSECRET);
    res.cookie("mixueforlife", token, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24
    });
    res.redirect("/index");
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      errors.push("Email sudah terdaftar");
      return res.render("daftar", { errors });
    }
    return res.status(500).send("Terjadi kesalahan server.");
  }
});

app.get('/admin', mustBeAdmin, (req, res) => {
  const products = db.prepare("SELECT * FROM products").all();
  res.render('admin', { user: req.user, products });
});

app.get("/editproduk", mustBeAdmin, (req, res) => {
  const products = db.prepare("SELECT * FROM products").all();
  res.render("editproduk", { user: req.user, products });
});

app.post('/editproduk', mustBeAdmin, (req, res) => {
  const { products } = req.body;

  const stmt = db.prepare('UPDATE products SET price = ?, stock = ? WHERE id = ?');

  const update = db.transaction(() => {
    for (const product of products) {
      stmt.run(product.price, product.stock, product.id);
    }
  });

  try {
    update();
    res.redirect('/editproduk');
  } catch (err) {
    console.error("Gagal update produk:", err);
    res.status(500).send("Terjadi kesalahan saat mengupdate produk.");
  }
});

app.get("/index", (req, res) => {
  const products = db.prepare("SELECT * FROM products WHERE stock > 0").all();

  const productsByCategory = {};
  for (let i = 0; i <= 6; i++) {
    productsByCategory[i] = [];
  }
  products.forEach(product => {
    productsByCategory[product.is_featured].push(product);
  });

  const categoryTitles = {
    0: "Produk Unggulan",
    1: "Fresh Ice Cream",
    2: "Real Fruit Tea",
    3: "Milk Tea",
    4: "Fresh Tea",
    5: "Coffee",
    6: "Kategori lainnya akan segera datang!"
  };

  let cart = [];
  if (req.user) {
    const rows = db.prepare(`
      SELECT c.id AS cart_id, c.quantity, c.selected, p.*
      FROM carts c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `).all(req.user.userid);

    cart = rows.map(row => ({
      cart_id: row.cart_id,
      quantity: row.quantity,
      selected: row.selected === 1,
      product: {
        id: row.id,
        name: row.name,
        price: row.price,
        is_featured: row.is_featured,
        image_url: row.image_url,
        description: row.description,
        stock: row.stock
      }
    }));
  }

  res.render("index", {
    user: req.user,
    categoryTitles,
    productsByCategory,
    cart,
    cartCount: req.user ? getCartItemCount(req.user.userid) : 0
  });
});

app.get('/profil', mustBeLoggedin, (req, res) => {
  const userId = req.user.userid;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const profile = getUserProfile(userId) || {};
  res.render('profil', { user, profile });
});

// Route edit profil GET
app.get('/editprofil', mustBeLoggedin, (req, res) => {
  const userId = req.user.userid;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const profile = getUserProfile(userId) || {};
  res.render('editprofil', { user, profile });
});

// Route edit profil POST dengan upload foto
app.post('/editprofil', mustBeLoggedin, upload.single('profile_image'), (req, res) => {
  const { full_name, phone, address } = req.body;

  if (!full_name || !phone || !address) {
    return res.status(400).send('Data profil tidak lengkap');
  }

  const existing = db.prepare("SELECT * FROM user_profiles WHERE user_id = ?").get(req.user.userid);

  let photoFilename = existing ? existing.profile_image : null;
  if (req.file) {
    photoFilename = req.file.filename;
  }

  if (existing) {
    db.prepare(`UPDATE user_profiles SET full_name = ?, phone = ?, address = ?, profile_image = ? WHERE user_id = ?`)
      .run(full_name, phone, address, photoFilename, req.user.userid);
  } else {
    db.prepare(`INSERT INTO user_profiles (user_id, full_name, phone, address, profile_image) VALUES (?, ?, ?, ?, ?)`)
      .run(req.user.userid, full_name, phone, address, photoFilename);
  }

  res.redirect('/profil');
});

app.get('/logout', (req, res) => {
  res.clearCookie('mixueforlife');
  res.redirect('/loginuser');
});

// Routes keranjang belanja
app.get("/keranjang", mustBeLoggedin, (req, res) => {
  // Ambil data carts + produk
  const carts = db.prepare(`
    SELECT c.id AS cart_id, c.quantity, c.selected, p.*
    FROM carts c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ?
  `).all(req.user.userid);

  // Ubah struktur supaya ada properti 'product' di tiap item
  const cartWithProduct = carts.map(item => ({
    cart_id: item.cart_id,
    quantity: item.quantity,
    selected: item.selected,
    product: {
      id: item.id,
      name: item.name,
      price: item.price,
      image_url: item.image_url,
      stock: item.stock,
      // tambahkan properti produk lain kalau perlu
    }
  }));

  res.render('keranjang', {
    user: req.user,
    cart: cartWithProduct
  });
});

app.post("/add-to-cart", mustBeLoggedin, (req, res) => {
  const { product_id, quantity } = req.body;

  if (!product_id || !quantity || isNaN(quantity) || quantity < 1) {
    return res.status(400).send("Data cart tidak valid");
  }

  const product = db.prepare("SELECT * FROM products WHERE id = ? AND stock >= ?").get(product_id, quantity);
  if (!product) {
    return res.status(400).send("Produk tidak tersedia atau stok tidak cukup");
  }

  const existingCart = db.prepare("SELECT * FROM carts WHERE user_id = ? AND product_id = ?").get(req.user.userid, product_id);

  if (existingCart) {
    db.prepare("UPDATE carts SET quantity = quantity + ? WHERE id = ?").run(quantity, existingCart.id);
  } else {
    db.prepare("INSERT INTO carts (user_id, product_id, quantity, selected) VALUES (?, ?, ?, 1)").run(req.user.userid, product_id, quantity);
  }

  res.redirect('/keranjang');
});



// Update quantity
app.post('/keranjang/update-qty', mustBeLoggedin, (req, res) => {
  const { product_id, quantity } = req.body;
  const qty = parseInt(quantity);

  if (!product_id || isNaN(qty) || qty < 1) {
    return res.json({ success: false, message: 'Data tidak valid' });
  }

  // Cek stok produk
  const product = db.prepare('SELECT stock FROM products WHERE id = ?').get(product_id);
  if (!product || product.stock < qty) {
    return res.json({ success: false, message: 'Stok tidak cukup' });
  }

  // Update quantity di keranjang
  const info = db.prepare('UPDATE carts SET quantity = ? WHERE user_id = ? AND product_id = ?')
    .run(qty, req.user.userid, product_id);

  if (info.changes === 0) {
    return res.json({ success: false, message: 'Produk tidak ditemukan di keranjang' });
  }

  res.json({ success: true });
});

// Update selected checkbox
app.post('/keranjang/update-check', mustBeLoggedin, (req, res) => {
  const { product_id, selected } = req.body;
  if (!product_id || typeof selected === 'undefined') {
    return res.json({ success: false, message: 'Data tidak valid' });
  }

  const selValue = selected ? 1 : 0;

  const info = db.prepare('UPDATE carts SET selected = ? WHERE user_id = ? AND product_id = ?')
    .run(selValue, req.user.userid, product_id);

  if (info.changes === 0) {
    return res.json({ success: false, message: 'Produk tidak ditemukan di keranjang' });
  }

  res.json({ success: true });
});

// Delete product from cart
app.post('/keranjang/delete', mustBeLoggedin, (req, res) => {
  const { product_id } = req.body;
  if (!product_id) {
    return res.json({ success: false, message: 'Data tidak valid' });
  }

  const info = db.prepare('DELETE FROM carts WHERE user_id = ? AND product_id = ?')
    .run(req.user.userid, product_id);

  if (info.changes === 0) {
    return res.json({ success: false, message: 'Produk tidak ditemukan di keranjang' });
  }

  res.json({ success: true });
});


// Route GET untuk menampilkan halaman checkout
app.get('/checkout', mustBeLoggedin, (req, res) => {
  // Ambil produk yang ada di keranjang dan selected = 1
  const selectedItems = db.prepare(`
    SELECT c.id AS cart_id, c.quantity, p.*
    FROM carts c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = ? AND c.selected = 1
  `).all(req.user.userid);

  if (selectedItems.length === 0) {
    return res.redirect('/keranjang'); // Kalau gak ada selected, redirect ke keranjang
  }

  res.render('checkout', {
    user: req.user,
    cart: selectedItems,
  });
});

// Route POST untuk proses checkout
app.post('/checkout', mustBeLoggedin, (req, res) => {
  const userId = req.user.userid;
  let selectedIds = req.body.selected; // array dari checkbox

  if (!selectedIds) {
    return res.status(400).send("Tidak ada produk yang dipilih untuk checkout.");
  }

  // Jika hanya 1 produk, bisa berupa string, ubah jadi array
  if (typeof selectedIds === 'string') {
    selectedIds = [selectedIds];
  }

  // Ambil data produk dari carts user yang selected sesuai id yg dikirim
  const placeholders = selectedIds.map(() => '?').join(',');
  const query = `SELECT c.*, p.name, p.price, p.stock 
                 FROM carts c 
                 JOIN products p ON c.product_id = p.id 
                 WHERE c.user_id = ? AND c.product_id IN (${placeholders})`;

  const params = [userId, ...selectedIds];
  const selectedCarts = db.prepare(query).all(...params);

  if (selectedCarts.length === 0) {
    return res.status(400).send("Produk terpilih tidak ditemukan di keranjang.");
  }

  // Render halaman form checkout, kirim data produk dan user
  res.render('checkout', { user: req.user, cartItems: selectedCarts });
});



// Start server
app.listen(3000, () => {
  console.log("Server berjalan di http://localhost:3000");
});
