const jwt = require('jsonwebtoken');
const secretKey = 'your_secret_key'; // Thay đổi thành khóa bí mật của bạn

exports.adminLogin = (req, res) => {
    res.render('account/adminLogin'); // Hiển thị trang đăng nhập
};

exports.handleLogin = (req, res) => {
    const { username, password } = req.body;

    console.log('Username:', username); // Kiểm tra username
    console.log('Password:', password); // Kiểm tra password

    // Tài khoản và mật khẩu giả
    const hardcodedUsername = 'admin';
    const hardcodedPassword = '123';

    if (username === hardcodedUsername && password === hardcodedPassword) {
        // Tạo token
        const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        console.log('Token:', token); // Kiểm tra token

        // Lưu token vào cookie
        res.cookie('token', token, { httpOnly: true });

        // Chuyển đến trang sau khi đăng nhập thành công
        res.redirect('/protectedRoute');
    } else {
        return res.status(401).send('Thông tin đăng nhập không hợp lệ!');
    }
};

exports.protectedRoute = (req, res) => {
    const username = req.user.username; // Lấy username từ token
    res.render('protectedRoute', { username });
};
