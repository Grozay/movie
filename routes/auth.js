var express = require('express');
var router = express.Router();
const authController = require('../controllers/authController');

/* GET users listing. */
router.get('/adminlogin', authController.adminLogin);
router.post('/adminlogin', authController.storeAdminLogin);
router.get('/dashboard', authController.dashboard);
router.get('/logout', authController.logout);
module.exports = router;
