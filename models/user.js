var mongoose = require('mongoose');
var Schema = mongoose.Schema;
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

module.exports = mongoose.model('User', User);