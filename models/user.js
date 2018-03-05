let mong = require('mongoose');
let Schema = mong.Schema;
let passportLocalMongoose = require('passport-local-mongoose');

let UserSchema = new Schema({
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

UserSchema.plugin(passportLocalMongoose);

// model contains authenticate(), serializeUser(), and deserializeUser() methods
var model = mong.model('User', UserSchema);

module.exports = model;