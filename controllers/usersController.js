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


exports.homeUser = (req, res) => {
    if (!req.cookies.token) {
        return res.render('account/homeUser', { isLoggedIn: false });
    }
    try {
        const decodedToken = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
        if (decodedToken.role === 'user') {
            res.render('account/homeUser', { isLoggedIn: true }); 
        } else {
            res.render('account/homeUser', { isLoggedIn: false });
        }
    } catch (error) {
        console.error('JWT verification failed', error);
        res.render('account/homeUser', { isLoggedIn: false });
    }
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
                return res.status(401).render('account/questLogin', {
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

            const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.cookie('token', token);
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

            if (decodedToken.role === 'admin') {
                return res.render('account/questLogin', {
                    errors: [{ msg: 'You do not have permission' }],
                    username: username
                });
            } else {
                res.redirect('/users/homeUser'); 
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
        .notEmpty().withMessage('Username is required'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('account/register', {
                errors: errors.array(),
                username: req.body.username
            });
        }

        try {
            const { username, password } = req.body;
            const user = await User.findOne({ username });
            if (user) {
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
        }
    }
];

exports.logoutUser = (req, res) => {
    res.clearCookie('token');
    res.redirect('/users/guestlogin');
};

