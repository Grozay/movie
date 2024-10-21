const User = require('../models/user.model');  
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

exports.adminLogin = (req, res) => {
    res.render('account/adminLogin');
}

exports.storeAdminLogin = [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('account/adminLogin', {
                errors: errors.array(),
                username: req.body.username
            });
        }
        try {
            const { username, password } = req.body;
            const user = await User.findOne({ username });
            if (!user) {
                return res.status(401).render('account/adminLogin', {
                    errors: [{ msg: 'Invalid username or password' }],
                    username: username
                });
            }

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.render('account/adminLogin', {
                    errors: [{ msg: 'Invalid username or password' }],
                    username: username
                });
            }

            const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.cookie('token', token);
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

            if (decodedToken.role !== 'admin') {
                return res.render('account/adminLogin', {
                    errors: [{ msg: 'You do not have permission' }],
                    username: username
                });
            } else {
                res.redirect('/auth/dashboard'); 
            }
        } catch (error) {
            console.error(error);
            return res.render('account/adminLogin', {
                errors: [{ msg: 'Internal server error' }],
                username: req.body.username
            });
        }
    }
]

exports.dashboard = (req, res) => {
    if (!req.cookies.token) {
        return res.render('account/dashboard', { isLoggedIn: false });
    }
    try {
        const decodedToken = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
        if (decodedToken.role === 'admin') {
            res.render('account/dashboard', { isLoggedIn: true }); 
        } else {
            res.render('account/dashboard', { isLoggedIn: false });
        }
    } catch (error) {
        console.error('JWT verification failed', error);
        res.render('account/dashboard', { isLoggedIn: false });
    }
};

exports.logout = (req, res) => {
    res.clearCookie('token');
    res.redirect('/auth/adminlogin');
};


