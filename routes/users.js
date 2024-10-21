var express = require('express');
var router = express.Router();
const usersController = require('../controllers/usersController');

// router.get('/admin-login', usersController.adminLogin);
router.get('/guestlogin', usersController.guestLogin);
router.get('/register', usersController.register);
router.post('/userLogin', usersController.userLogin);
router.post('/createRegister', usersController.createRegister);
router.get('/homeUser', usersController.homeUser);
router.get('/', usersController.index);
router.get('/logout', usersController.logoutUser);
module.exports = router;
