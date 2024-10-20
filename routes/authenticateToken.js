const jwt = require('jsonwebtoken');
const secretKey = 'your_secret_key'; // Khóa bí mật của bạn

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // Hoặc req.headers.authorization nếu bạn gửi token qua header
    
    if (!token) return res.sendStatus(401); // Không có token
    
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403); // Token không hợp lệ
        req.user = user; // Lưu thông tin người dùng vào request
        next(); // Tiếp tục đến middleware tiếp theo hoặc route handler
    });
};

module.exports = authenticateToken;
