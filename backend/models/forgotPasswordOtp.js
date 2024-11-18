import mongoose from "mongoose";

const forgotPasswordOtpSchema = new mongoose.Schema({
	email: { type: String, required: true, unique: true },
	forgotPasswordOtp: { type: Number, required: true },
	secret : { type: String },
	createdAt: { type: Date, default: Date.now, expires: 600 }, // Apply expiration to `createdAt`

});

const forgotPasswordOtpModel = mongoose.model("ForgotPassword", forgotPasswordOtpSchema);

export default forgotPasswordOtpModel;