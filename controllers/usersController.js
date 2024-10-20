const User = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');



// exports.adminLogin = (req, res) => {
//     res.render('account/adminLogin');
// };
exports.index = (req, res) => {
    res.render('account/index');
};

exports.register = (req, res) => {
    res.render('account/register');
};

exports.guestLogin = (req, res) => {
    res.render('account/questLogin');
};

exports.userLogin = [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('account/questLogin', {
                errors: errors.array(),
                username: req.body.username
            });
        }
          
        try {
            const { username, password } = req.body;
            const user = await User.findOne({ username });
            if (!user) {
                return res.render('account/questLogin', {
                    errors: [{ msg: 'Invalid username or password' }],
                    username: username
                });
            }

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.render('account/questLogin', {
                    errors: [{ msg: 'Invalid username or password' }],
                    username: username
                });
            }

            const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token);
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

            if (decodedToken.role === 'admin') {
                res.redirect('/users/guestlogin');
            } else {
                res.redirect('/');
            }
        } catch (error) {
            console.error(error);
            return res.render('account/questLogin', {
                errors: [{ msg: 'Internal server error' }],
                username: req.body.username
            });
        }
    }
];



exports.createRegister = [
    body('username')
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
        .matches(/\d/).withMessage('Password must contain at least one number')
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter'),

    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Nếu có lỗi, render lại trang đăng ký với thông báo lỗi
            return res.render('account/register', {
                errors: errors.array(),
                username: req.body.username // Giữ lại username nếu có lỗi
            });
        }

        try {
            const { username, password } = req.body;
            const user = await User.findOne({ username });
            if (user) {
                // Thông báo lỗi nếu người dùng đã tồn tại
                return res.render('account/register', {
                    errors: [{ msg: 'User already exists' }],
                    username: req.body.username
                });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({ username, password: hashedPassword });
            await newUser.save();
            res.redirect('/users/guestlogin');
        } catch (error) {
            console.error(error);
            res.render('account/register', {
                errors: [{ msg: 'Internal server error' }],
                username: req.body.username
            });
        }
    }
];

