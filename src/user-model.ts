import mongoose from 'mongoose';
const { Schema } = mongoose;
import PassportLocalMongoose from 'passport-local-mongoose';
import {
  Document,
  PassportLocalDocument,
  PassportLocalModel
} from 'mongoose';
import { User as UserT } from './types/user';

type User = UserT & PassportLocalDocument;

const UserSchema = new Schema(
  {
    _id: String,
    username: String,
    fullname: String,
    password: String,
    email: String,
    enabled: Boolean
  }, 
  { 
    toObject: {
      versionKey: false
    }
  }
);

// eslint-disable-next-line @typescript-eslint/no-empty-interface
interface UserModel <T extends Document> extends PassportLocalModel<T> {}


UserSchema.plugin(PassportLocalMongoose);

export const UserModel: UserModel<User> = (function() {
  // model contains authenticate(), serializeUser(), and deserializeUser() methods
  return mongoose.model<User>('User', UserSchema);
})();

export type UserDoc = PassportLocalDocument & Document;
