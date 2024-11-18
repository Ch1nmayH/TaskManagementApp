import User from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";


const adminAuth = async (req, res, next) => {
	try {
		const token = req.cookies.token;
		if (!token) {
			return res.status(401).json({ message: "You are not Authenticated" });
		}

		const verified = jwt.verify(token, process.env.JWT_SECRET);
		if (!verified) {
			return res.status(401).json({ message: "Token Verification Failed" });
		}
		const email = verified.email;
		let user = await User.findOne({ email });

		if (!user.isAdmin) {
			return res
				.status(401)
				.json({ message: "You need to be admin to view this page" });
		}
		next();
	} catch (error) {
		res.status(500).json({ message: error.message });
		next();
	}
};


const auth = async (req, res, next) => {
	try {
		const token = req.cookies.token;
		if (!token) {
			return res.status(401).json({ message: "You are not Authenticated" });
		}
		const verified = jwt.verify(token, process.env.JWT_SECRET);
		if (!verified) {
			return res.status(401).json({ message: "Token Verification Failed" });
		}
		next();
	} catch (error) {
		res.status(500).json({ message: error.message });
		next();
	}
};
export {adminAuth, auth};