import express from "express";
import session from "express-session";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, "metro.db"));
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 1000*60*60*12 }
}));
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  capacity INTEGER NOT NULL DEFAULT 4,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  guests INTEGER NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  room_id INTEGER NOT NULL,
  comment TEXT,
  alcohol TEXT NOT NULL DEFAULT 'without',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS news (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  image TEXT,
  published_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  admin_name TEXT,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const adminCount = db.prepare("SELECT COUNT(*) c FROM admins").get().c;
if (!adminCount) {
  const seed = [
    ["admin1", "metro-admin-1", "Администратор 1"],
    ["admin2", "metro-admin-2", "Администратор 2"],
    ["admin3", "metro-admin-3", "Администратор 3"]
  ];
  const stmt = db.prepare("INSERT INTO admins(username,password_hash,name) VALUES(?,?,?)");
  for (const [u,p,n] of seed) stmt.run(u, bcrypt.hashSync(p, 10), n);
}
const roomCount = db.prepare("SELECT COUNT(*) c FROM rooms").get().c;
if (!roomCount) {
  const stmt = db.prepare("INSERT INTO rooms(id,name,capacity) VALUES(?,?,?)");
  stmt.run(1, "Зал 1", 8);
  stmt.run(2, "Зал 2", 10);
  stmt.run(3, "Зал 3", 6);
}

function adminOnly(req,res,next){
  if (!req.session.adminId) return res.status(401).json({error:"Требуется вход администратора"});
  next();
}
function logAction(req, action, details=""){
  db.prepare("INSERT INTO activity_log(admin_id,admin_name,action,details) VALUES(?,?,?,?)")
    .run(req.session.adminId, req.session.adminName || "", action, details);
}

app.get("/api/rooms", (req,res) => {
  res.json(db.prepare("SELECT id,name,capacity FROM rooms WHERE active=1 ORDER BY id").all());
});

app.get("/api/news", (req,res) => {
  res.json(db.prepare("SELECT * FROM news ORDER BY published_at DESC, id DESC LIMIT 20").all());
});

app.post("/api/bookings", (req,res) => {
  const {name,phone,guests,date,time,room_id,comment="",alcohol="without"} = req.body;
  if (!name || !phone || !guests || !date || !time || !room_id) {
    return res.status(400).json({error:"Заполните обязательные поля"});
  }
  const room = db.prepare("SELECT * FROM rooms WHERE id=? AND active=1").get(room_id);
  if (!room) return res.status(400).json({error:"Комната не найдена"});
  if (Number(guests) > Number(room.capacity)) {
    return res.status(400).json({error:`В комнате ${room.name} базовая вместимость ${room.capacity} гостей. Дополнительные гости оплачиваются отдельно.`});
  }
  const conflict = db.prepare(`
    SELECT COUNT(*) c FROM bookings
    WHERE room_id=? AND date=? AND time=? AND status IN ('pending','confirmed')
  `).get(room_id,date,time).c;
  if (conflict) return res.status(409).json({error:"На это время комната уже забронирована. Выберите другое время."});

  const info = db.prepare(`
    INSERT INTO bookings(name,phone,guests,date,time,room_id,comment,alcohol)
    VALUES(?,?,?,?,?,?,?,?)
  `).run(name,phone,Number(guests),date,time,room_id,comment,alcohol);

  res.json({ok:true,id:info.lastInsertRowid});
});

app.post("/api/feedback", (req,res) => {
  const {name,phone="",text} = req.body;
  if (!name || !text) return res.status(400).json({error:"Заполните имя и сообщение"});
  db.prepare("INSERT INTO feedback(name,phone,text) VALUES(?,?,?)").run(name,phone,text);
  res.json({ok:true});
});

app.post("/api/admin/login", (req,res) => {
  const {username,password} = req.body;
  const admin = db.prepare("SELECT * FROM admins WHERE username=?").get(username);
  if (!admin || !bcrypt.compareSync(password,admin.password_hash)) {
    return res.status(401).json({error:"Неверный логин или пароль"});
  }
  req.session.adminId = admin.id;
  req.session.adminName = admin.name;
  logAction(req, "Вход", "Успешная авторизация");
  res.json({ok:true,name:admin.name});
});
app.post("/api/admin/logout", (req,res) => req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin/me", adminOnly, (req,res)=>res.json({name:req.session.adminName}));

app.get("/api/admin/bookings", adminOnly, (req,res) => {
  res.json(db.prepare(`
    SELECT b.*, r.name room_name FROM bookings b
    JOIN rooms r ON r.id=b.room_id
    ORDER BY b.date DESC, b.time DESC, b.id DESC
  `).all());
});
app.patch("/api/admin/bookings/:id", adminOnly, (req,res) => {
  const {status} = req.body;
  if (!["pending","confirmed","cancelled","completed"].includes(status)) return res.status(400).json({error:"Некорректный статус"});
  db.prepare("UPDATE bookings SET status=? WHERE id=?").run(status,req.params.id);
  logAction(req, "Изменение брони", `Бронь #${req.params.id}: статус ${status}`);
  res.json({ok:true});
});
app.get("/api/admin/feedback", adminOnly, (req,res) => {
  res.json(db.prepare("SELECT * FROM feedback ORDER BY id DESC").all());
});
app.post("/api/admin/news", adminOnly, (req,res) => {
  const {title,body,image="",published_at} = req.body;
  if (!title || !body || !published_at) return res.status(400).json({error:"Заполните заголовок, текст и дату"});
  const info = db.prepare("INSERT INTO news(title,body,image,published_at) VALUES(?,?,?,?)").run(title,body,image,published_at);
  logAction(req, "Создание новости", title);
  res.json({ok:true,id:info.lastInsertRowid});
});
app.patch("/api/admin/news/:id", adminOnly, (req,res) => {
  const {title,body,image="",published_at} = req.body;
  db.prepare("UPDATE news SET title=?,body=?,image=?,published_at=? WHERE id=?")
    .run(title,body,image,published_at,req.params.id);
  res.json({ok:true});
});
app.delete("/api/admin/news/:id", adminOnly, (req,res) => {
  db.prepare("DELETE FROM news WHERE id=?").run(req.params.id);
  logAction(req, "Удаление новости", `Новость #${req.params.id}`);
  res.json({ok:true});
});
app.patch("/api/admin/rooms/:id", adminOnly, (req,res) => {
  const {name,capacity,active=1} = req.body;
  db.prepare("UPDATE rooms SET name=?,capacity=?,active=? WHERE id=?")
    .run(name,Number(capacity),active?1:0,req.params.id);
  logAction(req, "Изменение комнаты", `Комната #${req.params.id}: ${name}, вместимость ${capacity}`);
  res.json({ok:true});
});

app.get("/admin", (req,res) => res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("/api/admin/rooms", adminOnly, (req,res) => {
  res.json(db.prepare("SELECT id,name,capacity,active FROM rooms ORDER BY id").all());
});
app.get("/api/admin/news", adminOnly, (req,res) => {
  res.json(db.prepare("SELECT * FROM news ORDER BY published_at DESC, id DESC").all());
});
app.get("/api/admin/log", adminOnly, (req,res) => {
  res.json(db.prepare("SELECT * FROM activity_log ORDER BY id DESC LIMIT 200").all());
});
app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`METRO site: http://localhost:${PORT}`));
            
