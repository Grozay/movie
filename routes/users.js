var express = require('express');
var router = express.Router();
const usersController = require('../controllers/usersController');
const authController = require('../controllers/authController');
router.get('/adminLogin', authController.adminLogin);
router.get('/guestlogin', usersController.guestLogin);
router.get('/register', usersController.register);
router.post('/userLogin', usersController.userLogin);
router.post('/createRegister', usersController.createRegister);
router.get('/', usersController.index);

module.exports = router;
