const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Route hiển thị trang đăng nhập
router.get('/adminLogin', authController.adminLogin);

// Route xử lý đăng nhập
router.post('/adminLogin', authController.handleLogin);

// Route bảo vệ
router.get('/protectedRoute', authController.protectedRoute);

module.exports = router;