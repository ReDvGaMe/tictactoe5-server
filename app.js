var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

// DB 설정
var mongodb = require('mongodb');
var MongoClient = mongodb.MongoClient;

// 암호화 모듈 설정
// var bcrypt = require('bcrypt');
// const saltRounds = 10;

// 세션 설정


var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// DB 연결
async function connectDB() {
  var databaseUrl = 'mongodb://localhost:27017';

  try {
    const database = await MongoClient.connect(databaseUrl, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Database connected successfully');
    app.set('database', database.db('tictactoe'));

    // 연결 종료 처리
    process.on('SIGINT', async () => {
      await database.close();
      console.log('Database connection closed');
      process.exit(0);
    });
  }
  catch(error){
    consol.error('Database connection failed: ', error);
    process.exit(1);
  }
}

connectDB().catch(err => {
  consol.error('Failed to connect to the database: ',err);
  process.exit(1);
})

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
