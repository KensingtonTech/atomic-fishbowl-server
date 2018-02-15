var mong = require('mongoose');
var Schema = mong.Schema;
var passportLocalMongoose = require('passport-local-mongoose');

var User = new Schema({
  id: String,
  username: String,
  fullname: String,
  password: String,
  email: String,
  enabled: Boolean
}, { 
    toObject: {
      versionKey: false,
      transform: (doc, ret, options) => { delete ret._id; return ret; }
    }
});

User.plugin(passportLocalMongoose);

// model contains authenticate(), serializeUser(), and deserializeUser() methods
let model = mong.model('User', User);

module.exports = model;