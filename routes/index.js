var express = require('express');
var hash = require('pbkdf2-password')();
var mongoose = require('mongoose');

var router = express.Router();

mongoose.connect(process.env.MONGODB_URI);
mongoose.Promise = global.Promise;
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
var Schema = mongoose.Schema;
var UserSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  salt: {
    type: String,
    required: true
  },
  hash: {
    type: String,
    required: true
  }
});
var SensorDataSchema = new Schema({
  type: {
    type: String,
    required: true
  },
  temp: {
    type: Number,
    required: true
  },
  humidity: {
    type: Number,
    required: true
  },
  ssid: {
    type: String,
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});
var SensorSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  ssid: {
    type: String,
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'users',
    required: true
  }
})
var UserModel = mongoose.model('users', UserSchema);
var SensorDataModel = mongoose.model('sensor_data', SensorDataSchema);
var SensorModel = mongoose.model('sensors', SensorSchema);

function restrict(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    req.session.error = 'Access denied!';
    res.redirect('/login');
  }
}

function validateEmail(email) {
  var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(email);
}

function authenticate(email, pass, fn) {
  if (!module.parent) console.log('authenticating %s:%s', email, pass);
  UserModel.findOne({ email: email }, (err, result) => {
    if (err) throw err;
    if (!result) return fn(new Error('cannot find user'));
    hash({ password: pass, salt: result.salt }, (err, pass, salt, hash) => {
      if (err) return fn(err);
      if (hash === result.hash) return fn(null, result);
      fn(new Error('invalid password'));
    });
  });
}

function register(name, email, password, password_conf, fn) {
  var user = new UserModel({
    name: name,
    email: email
  });
  hash({ password: password }, (err, pass, salt, hash) => {
    if (err) return fn(err);
    user.salt = salt;
    user.hash = hash;
    UserModel.findOne({ email: email }, (err, result) => {
      if (err) return fn(new Error('An error occurred. Error: ', err));
      if (result) return fn(new Error('A user with that email already exists!'));
      user.save(function (err) {
        if (err) return fn(new Error('An error occurred. Error: ', err));
        else return fn(null, user);
      });
    });
  });
}

function addSensor(name, ssid, userId, fn) {
  var sensor = new SensorModel({
    name: name,
    ssid: ssid,
    user: userId
  });
  sensor.save(function (err) {
    if (err) return fn(new Error('An error occurred. Error: ', err));
    else return fn(null, sensor);
  });
}

function sensorData(type, temp, humidity, ssid, fn) {
  var sensorData = new SensorDataModel({
    type: type,
    temp: temp,
    humidity: humidity,
    ssid: ssid
  });
  sensorData.save(function (err) {
    if (err) return fn(new Error('An error occurred. Error: ', err));
    else return fn(null, sensorData);
  });
}

router.use(function (req, res, next) {
  var err = req.session.error;
  var msg = req.session.success;
  delete req.session.error;
  delete req.session.success;
  res.locals.message = '';
  if (err) res.locals.message = '<p class="msg error">' + err + '</p>';
  if (msg) res.locals.message = '<p class="msg success">' + msg + '</p>';
  next();
});

router.get('/', function (req, res) {
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
  res.redirect('/login.html');
});

router.post('/login', function (req, res) {
  authenticate(req.body.username, req.body.password, function (err, user) {
    if (user) {
      req.session.regenerate(function () {
        req.session.user = user;
        req.session.success = 'Authenticated as ' + user.name
          + ' click to <a href="/logout">logout</a>. '
          + ' You may now access <a href="/restricted">/restricted</a>.';
        res.redirect('/dash.html');
      });
    } else {
      req.session.error = 'Authentication failed, please check your '
        + ' username and password.';
      res.redirect('back');
    }
  });
});

router.get('/register', function (req, res) {
  res.redirect('/register.html');
});

router.post('/register', function (req, res) {
  var name = req.body.name.trim();
  var email = req.body.email.trim();
  var password = req.body.password.trim();
  var password_conf = req.body.password_conf.trim();
  var errorFields = {};
  if (!name) errorFields['name'] = 'name is required.';
  else res.locals.name = name;
  if (!email) errorFields['email'] = 'email is required.';
  else if (!validateEmail(email)) errorFields['email'] = 'invalid email';
  else res.locals.email = email;
  if (!password) errorFields['password'] = 'password is required.';
  else if (password !== password_conf) errorFields['password_conf'] = 'passwords don\'t match.';
  if (Object.keys(errorFields).length > 0) {
    res.locals.errorFields = errorFields;
    res.render('register');
    return;
  }
  register(name, email, password, password_conf, function (err, user) {
    if (user) {
      req.session.regenerate(function () {
        req.session.user = user;
        req.session.success = 'Authenticated as ' + user.name
          + ' click to <a href="/logout">logout</a>. '
          + ' You may now access <a href="/restricted">/restricted</a>.';
        res.redirect('/dash.html');
      });
    } else {
      if (err) req.session.error = err.message;
      res.redirect('back');
    }
  });
});

router.get('/sensor/add', restrict, function (req, res) {
  res.render('addSensor');
});

router.post('/sensor/add', restrict, function (req, res) {
  var name = req.body.name.trim();
  var ssid = req.body.ssid.trim();
  var userId = req.session.user._id;
  var errorFields = {};
  if (!name) errorFields['name'] = 'name is required.';
  else res.locals.name = name;
  if (!ssid) errorFields['ssid'] = 'SSID is required.';
  else res.locals.ssid = ssid;
  if (Object.keys(errorFields).length > 0) {
    res.locals.errorFields = errorFields;
    res.render('addSensor');
    return;
  }
  addSensor(name, ssid, userId, function (err, data) {
    if (data) {
      req.session.success = 'Added sensor ' + ssid + '.';
      res.redirect('back');
    } else {
      if (err) req.session.error = err.message;
      res.redirect('back');
    }
  });
});

router.get('/sensor/data', function (req, res) {
  var type = req.body.type.trim();
  var temp = parseFloat(req.body.temp);
  var humidity = parseFloat(req.body.humidity);
  var ssid = req.body.ssid.trim();
  sensorData(type, temp, humidity, ssid, function (err, data) {
    if (data) {
      res.redirect('back');
    } else {
      if (err) req.session.error = err.message;
      res.redirect('back');
    }
  });
});

module.exports = router;
