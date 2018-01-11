var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken')
var randtoken = require('rand-token')

var passport = require('passport')
var JwtStrategy = require('passport-jwt').Strategy
var ExtractJwt = require('passport-jwt').ExtractJwt

var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', index);
app.use('/users', users);

var refreshTokens = {}
var SECRET = "SECRETO_PARA_ENCRIPTACION"
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.post('/login', function (req, res, next) {
  var username = req.body.username
  var password = req.body.password

  console.log('app.post(\'/login\'): ', req.body)
  var user = {
    'username': username,
    'role': 'admin',
  }
  var token = jwt.sign(user, SECRET, { expiresIn: 300 })
  var refreshToken = randtoken.uid(256)

  refreshTokens[refreshToken] = username

  res.json({token: 'JWT ' + token, refreshToken: refreshToken})
});

app.post('/token', function (req, res, next) {
  var username = req.body.username
  var refreshToken = req.body.refreshToken

  console.log('app.post(\'/token\'): ', req.body)
  if((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == username)) {
    var user = {
      'username': username,
      'role': 'admin',
    }
    var token = jwt.sign(user, SECRET, { expiresIn: 300 })
    res.json({token: 'JWT ' + token})
  }
  else {
    res.send(401)
  }
})

app.post('/token/reject', function (req, res, next) {
  var refreshToken = req.body.refreshToken
  if(refreshToken in refreshTokens) {
    delete refreshTokens[refreshToken]
  }
  res.send(204)
})

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser(function (user, done) {
  console.log('passport.serializeUser: ', user)
  done(null, user.username)
})

/*
passport.deserializeUser(function (username, done) {
  done(null, username)
})
*/

var opts = {}
// Setup JWT options
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt")
opts.secretOrKey = SECRET

passport.use(new JwtStrategy(opts, function (jwtPayload, done) {
  //If the token has expiration, raise unauthorized
  var expirationDate = new Date(jwtPayload.exp * 1000)
  if(expirationDate < new Date()) {
    return done(null, false);
  }

  var user = jwtPayload
  console.log('passport.use: ', user)
  done(null, user)
}))

app.get('/test_jwt', passport.authenticate('jwt'), function (req, res) {
  res.json({success: 'You are authenticated with JWT!', user: req.user})
})

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
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
