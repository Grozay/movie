var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var jwt = require('jsonwebtoken'); // Nhập jsonwebtoken
var logger = require('morgan');
const { connect } = require('./config/db');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var authRouter = require('./routes/auth'); 
var app = express();

connect();
// Khóa bí mật để tạo token (nên giữ bí mật)
const secretKey = 'your_secret_key'; // Thay đổi thành khóa của bạn

// Middleware xác thực token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token; // Lấy token từ cookie
    
    if (!token) return res.sendStatus(401); // Không có token, từ chối truy cập (401 Unauthorized)
    
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403); // Token không hợp lệ, từ chối truy cập (403 Forbidden)
        req.user = user; // Lưu thông tin người dùng vào request
        next(); // Tiếp tục đến middleware tiếp theo hoặc route handler
    });
};

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/auth', authRouter);
// catch 404 and forward to error handler
app.get('/protectedRoute', authenticateToken, (req, res) => {
  res.render('account/protectedRoute', { user: req.user });
});

app.use(function(req, res, next) {
  next(createError(404));
});


// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
