var express = require('express');
var hash = require('pbkdf2-password')();
var mongo = require('mongodb');
var router = express.Router();

var MongoClient = mongo.MongoClient;
var db;
MongoClient.connect('mongodb://localhost:27017', function (err, client) {
  if (err) throw err;
  db = client.db('project1');
});

function authenticate(name, pass, fn) {
  if (!module.parent) console.log('authenticating %s:%s', name, pass);
  db.collection('users').findOne({ name: name }, (err, result) => {
    if (err) throw err;
    if (!result) return fn(new Error('cannot find user'));
    hash({ password: pass, salt: result.salt }, (err, pass, salt, hash) => {
      if (err) return fn(err);
      if (hash === result.hash) return fn(null, result);
      fn(new Error('invalid password'));
    });
  });
}

function restrict(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    req.session.error = 'Access denied!';
    res.redirect('/login');
  }
}

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Project 1' });
});

router.get('/restricted', restrict, function (req, res) {
  res.send('Wahoo! restricted area, click to <a href="/logout">logout</a>');
});

router.get('/logout', function (req, res) {
  req.session.destroy(function () {
    res.redirect('/');
  });
});

router.get('/login', function (req, res) {
  var err = req.session.error;
  var msg = req.session.success;
  delete req.session.error;
  delete req.session.success;
  res.locals.message = '';
  if (err) res.locals.message = '<p class="msg error">' + err + '</p>';
  if (msg) res.locals.message = '<p class="msg success">' + msg + '</p>';
  res.render('login');
});

router.post('/login', function (req, res) {
  authenticate(req.body.username, req.body.password, function (err, user) {
    if (user) {
      req.session.regenerate(function () {
        req.session.user = user;
        req.session.success = 'Authenticated as ' + user.name
          + ' click to <a href="/logout">logout</a>. '
          + ' You may now access <a href="/restricted">/restricted</a>.';
        res.redirect('back');
      });
    } else {
      req.session.error = 'Authentication failed, please check your '
        + ' username and password.'
        + ' (use "tj" and "foobar")';
      res.redirect('/login');
    }
  });
});

router.get('/register', function (req, res) {
  res.render('register');
});

module.exports = router;
