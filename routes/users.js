var express = require('express');
var router = express.Router();
const usersController = require('../controllers/usersController');

/* GET users listing. */
// router.get('/admin-login', usersController.adminLogin);
router.get('/guestlogin', usersController.guestLogin);
router.get('/', usersController.index);
router.get('/register', usersController.register);
module.exports = router;
