import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
	firstName: { type: String, required: true },
	lastName: { type: String, required: true },
	email: { type: String, required: true, unique: true },
	mobile: { type: Number, required: true, unique: true, maxlength: 10 },
	password: { type: String, required: true },
	address: { type: String, required: false },
	isAdmin: { type: Boolean, required: true, default: false },
	isVerified: { type: Boolean, required: true, default: false },
	createdAt: { type: Date, default: Date.now },
});

userSchema.pre("save", async function (next) {
	try {
		const salt = await bcrypt.genSalt(10);
		this.password = await bcrypt.hash(this.password, salt);
		// console.log("Password Hashed", this.password);
		return next();
	} catch (error) {
		console.log(error);
		throw new Error(error);
		next();
	}
});

const userModel = mongoose.model("User", userSchema);
export default userModel;