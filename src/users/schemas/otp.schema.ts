import { Schema } from 'mongoose';

export const OtpSchema = new Schema({
  email: { type: String, unique: true },
  pin: {
    type: String,
    minlength: 6,
    maxlength: 6
  },
  createdAt: Date,
  expiryDate: Date,
  isVerified: {
    type: Boolean,
    default: false
  }
});
