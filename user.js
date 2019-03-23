// mongoose is loaded through a global

let mongooseSchema = mongoose.Schema;

var UserSchema = new mongooseSchema(
  {
    id: String,
    username: String,
    fullname: String,
    password: String,
    email: String,
    enabled: Boolean
  }, 
  { 
    toObject: {
      versionKey: false,
      transform: (doc, ret, options) => { delete ret._id; return ret; }
    }
  }
);

UserSchema.plugin( require('passport-local-mongoose') );

// model contains authenticate(), serializeUser(), and deserializeUser() methods
const MongooseModel = mongoose.model('User', UserSchema);

module.exports = MongooseModel;