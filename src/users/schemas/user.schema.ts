import { Schema } from 'mongoose';

export const UserSchema = new Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: Schema.Types.ObjectId,
    ref: "otps"
  }
});
