const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./db.sqlite');

// Cấu hình session
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'views')));

// Tạo bảng users nếu chưa tồn tại
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)`);

// Route cho trang chủ
app.get('/', (req, res) => {
    // Nếu người dùng đã đăng nhập, chuyển hướng tới trang welcome
    if (req.session.user) {
        res.redirect('/welcome');
    } else {
        // Nếu chưa đăng nhập, chuyển hướng tới trang đăng nhập
        res.redirect('/login');
    }
});

// Route đăng ký
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
        if (err) {
            return res.send('Tên người dùng đã tồn tại. Vui lòng chọn tên khác.');
        }
        res.redirect('/login');
    });
});

// Route đăng nhập
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            return res.send('Có lỗi xảy ra. Vui lòng thử lại.');
        }

        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.redirect('/welcome');
        } else {
            res.send('Sai tên đăng nhập hoặc mật khẩu');
        }
    });
});

// Route trang chào mừng sau khi đăng nhập thành công
app.get('/welcome', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
    } else {
        res.redirect('/login');
    }
});

// Route đăng xuất
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Khởi động server
app.listen(3000, () => {
    console.log('Server đang chạy tại http://localhost:3000');
});