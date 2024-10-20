
const User = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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

exports.userLogin = async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) {
           throw new Error('User not found');
        }
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if (!passwordMatch) {
            throw new Error('Invalid username or password');
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        
        if(decodedToken.role !== 'admin'){
            res.cookie('token', token); 
            res.redirect('/users/guestlogin');
        }else{
            res.cookie('token', token);
            res.redirect('/');
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


exports.createRegister = async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user) {
            throw new Error('User already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        // const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        res.redirect('/users/guestlogin');
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};