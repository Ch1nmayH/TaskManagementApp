import user from "../models/userModel.js";
import Otp from "../models/otpModel.js";
import bcrypt from "bcryptjs";
import generateOtp from "../config/otpGenerator.js";
import transporter from "../config/mailTransporter.js";
import jwt from "jsonwebtoken";
import ForgotPassword from "../models/forgotPasswordOtp.js";

import dotenv from "dotenv";
dotenv.config();

const signup = async (req, res, next) => {
  const { firstName, lastName, email, mobile, password } = req.body;
  try {
    const existingUser = await user.findOne({ email });
    const existingMobile = await user.findOne({ mobile });
    if (existingUser) {
      return res
        .status(200)
        .json({ message: "User already exists with this email" });
    }
    if (existingMobile) {
      return res
        .status(200)
        .json({ message: "User already exists with this mobile number" });
    }

    const newUser = await user.create({
      firstName,
      lastName,
      email,
      mobile,
      password,
    });

    const newAddress = await Address.create({
      user: newUser._id, // Ensure the userId is assigned to the `user` field
      name : `${newUser.firstName} ${newUser.lastName}`,
      address1 : "Karnatak university",
      address2 : "",
      city : "Dharwad",
      pinCode : "50003", // Ensure correct field is used
      state : "Karnataka",
      mobile : `${newUser.mobile}`
    });

    const encryptedEmail = jwt.sign(
      { email: newUser.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    let otp = generateOtp();
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Email Verification",
      text: `Your OTP for Email Verification is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log(`Email sent: ${info.response}`);
      }
    });

    const newOtpModel = await Otp.create({
      email,
      otp,
    });

    return res.status(201).json({
      message:
        "User Created Successfully, an otp has been sent to your email for account activation and email confirmation.",
      otp: otp,
      token: encryptedEmail,
    });
    next();
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const signin = async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(200).json({ message: "User not found" });
    }
    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );

    if (!isPasswordCorrect) {
      return res.status(200).json({ message: "Invalid password" });
    }

    if (existingUser.isVerified) {
      const token = jwt.sign(
        { email: existingUser.email, id: existingUser._id },
        process.env.JWT_SECRET
      );

      return res
        .status(201)
        .cookie("token", token, {
          httpOnly: true,
          secure: false,
        })
        .json({ user: existingUser, token });
    }

    const userToken = jwt.sign(
      { email: existingUser.email, id: existingUser._id },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      } // 1 hour
    );
    return res.status(200).json({
      message: "User not verified, please verify your email first",
      token: userToken,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const signOut = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(400).json({ message: "User not authenticated" });
    }
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    if (!decodedData) {
      return res.status(400).json({ message: "User not authenticated" });
    }

    res.clearCookie("token");
    res.status(200).json({ message: "Signout Successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const verify = async (req, res, next) => {
  let { token, otp } = req.body;
  otp = parseInt(otp);

  try {
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    if (!decodedData) {
      return res.status(200).json({ message: "Invalid token" });
    }
    const email = decodedData.email;
    const existingOtp = await Otp.findOne({ email });
    if (existingOtp.verified)
      return res.status(200).json({ message: "Email already verified" });

    if (existingOtp.otp === otp) {
      await Otp.findOne({ email }).updateOne({ verified: true });
      await user.findOne({ email }).updateOne({ isVerified: true });
      return res.status(200).json({ message: "Email Verified Successfully" });
    }

    return res.status(200).json({ message: "Invalid OTP" });
  } catch (error) {
    console.log(error.message);
    res.status(400).json({ message: error.message });
  }
};

const resendOtp = async (req, res, next) => {
  const { email } = req.body;
  try {
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(400).json({ message: "User not found" });
    }

    if (existingUser.isVerified) {
      return res.status(400).json({ message: "User already verified" });
    }

    let otp = generateOtp();
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Email Verification",
      text: `Your OTP for Email Verification is ${otp}`,
    };
    const newOtp = await Otp.findOne({ email });
    if (!newOtp) {
      await Otp.create({
        email,
        otp,
      });
    } else await Otp.findOne({ email }).updateOne({ otp });

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log(`Email sent: ${info.response}`);
      }
    });

    await Otp.findOne({ email }).updateOne({ otp });

    return res.status(200).json({ message: "Otp sent successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const getAllUsers = async (req, res) => {
  try {
    const users = await user.find({});
    res.status(200).json({ users });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const getUsers = async (req, res) => {
  try {

    if (req.query.isAdmin == "true") {
      const users = await user.find({ isAdmin: true });
      return res.status(200).json({ users });
    }

    const users = await user.find({ isAdmin: false});
    res.status(200).json({ users });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};


const bulkInsert = async (req, res, next) => {
  try {
    const users = req.body;

    // Validate the structure of the users data if needed
    if (!Array.isArray(users) || users.length === 0) {
      return res.status(400).json({ message: "Invalid user data format" });
    }

    // Insert users into the database
    await user.insertMany(users);
    res.status(200).json({ message: "Users inserted successfully" });
    next();
  } catch (error) {
    console.error("Error inserting users:", error);
    res.status(500).json({ message: "Server error", error });
    next();
  }
};

const checkAdminAuth = async (req, res, next) => {
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
    let User = await user.findOne({ email });

    if (!User.isAdmin) {
      return res
        .status(401)
        .json({ message: "You need to be admin to view this page" });
    }

    return res.status(200).json({ message: "success" });
    next();
  } catch (error) {
    res.status(500).json({ message: error.message });
    next();
  }
};


const checkAuth = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "You are not Authenticated" });
    }
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (!verified) {
      return res.status(401).json({ message: "Token Verification Failed" });
    }
    return res.status(200).json({ message: "success" });

    next();
  } catch (error) {
    res.status(500).json({ message: error.message });
    next();
  }
};

const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    await user.findByIdAndDelete(id);
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, email, mobile, password } = req.body;
    await user.findByIdAndUpdate(id, {
      firstName,
      lastName,
      email,
      mobile,
      password,
    });
    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const createUser = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      mobile,
      password,
      isVerified,
      isAdmin,
    
    } = req.body;
    const newUser = await user.create({
      firstName,
      lastName,
      email,
      mobile,
      password,
      isVerified,
      isAdmin,
    });
    const newAddress = new Address({
      user: newUser._id, // Ensure the userId is assigned to the `user` field
      name : `${newUser.firstName} ${newUser.lastName}`,
      address1 : "Karnatak university",
      address2 : "",
      city : "Dharwad",
      pinCode : "50003", // Ensure correct field is used
      state : "Karnataka",
      mobile : `${newUser.mobile}`
    });

    await newAddress.save(); // Save the new address to the database
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const changePassword = async (req, res) => {
  try {
    const token = req.cookies.token;
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (!verified.id) {
      return res.status(401).json({ message: "You are not authenticated" });
    }
    const password = req.body.password;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await user.findByIdAndUpdate(verified.id, { password: hashedPassword });
    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};


const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(400).json({ message: "User not found" });
    }

    if (!existingUser.isVerified) {
      return res.status(400).json({ message: "User not verified" });
    }

    if (existingUser.isAdmin) {
      return res.status(400).json({ message: "Admin cannot reset password" });
    }

    let forgotPasswordOtp = generateOtp();

    const alreadyExists = await ForgotPassword.findOne({ email });
    if (alreadyExists) {
      await ForgotPassword.findOne({ email }).updateOne({ forgotPasswordOtp });
    } else {
      const ForgotPasswordOtpSave = await ForgotPassword.create({
        email,
        forgotPasswordOtp,
      });
    }
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Forgot Password",
      text: `Your OTP reset your password is ${forgotPasswordOtp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log(`Email sent: ${info.response}`);
      }
    });

    const encryptedEmail = jwt.sign(
      { email: existingUser.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    return res
      .status(200)
      .json({ message: "Otp sent successfully", token: encryptedEmail });
  } catch (error) {
    console.log(error.message);
    res.status(400).json({ message: error.message });
  }
};

const forgotPasswordVerify = async (req, res) => {
  let { token, otp } = req.body;
  otp = parseInt(otp);
  try {
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    if (!decodedData) {
      return res.status(200).json({ message: "Invalid token" });
    }
    const email = decodedData.email;
    const existingOtp = await ForgotPassword.findOne({ email });

    if (!existingOtp) {
      return res.status(200).json({ message: "Invalid Email" });
    }

    let randomSecret = Math.floor(1000 + Math.random() * 9000).toString();
    const secret = jwt.sign({ secret: randomSecret }, process.env.JWT_SECRET);
    if (existingOtp.forgotPasswordOtp === otp) {
      const addSecret = await ForgotPassword.updateOne({
        email,
        secret: randomSecret,
      });
      return res
        .status(200)
        .json({ message: "Otp Verified Successfully", token, secret });
    }
    return res.status(200).json({ message: "Invalid OTP" });
  } catch (error) {
    console.log(error.message);
    res.status(400).json({ message: error.message });
  }
};

const newPassword = async (req, res) => {
  try {
    const { password, token, secret } = req.body;
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    if (!decodedData) {
      return res.status(200).json({ message: "Invalid token" });
    }
    const email = decodedData.email;
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(200).json({ message: "Invalid user" });
    }
    const decodedSecret = jwt.verify(secret, process.env.JWT_SECRET);
    if (!decodedSecret) {
      return res.status(200).json({ message: "Invalid secret" });
    }

    const matchSecret = await ForgotPassword.findOne({
      email,
      secret: decodedSecret.secret,
    });
    if (!matchSecret) {
      return res.status(200).json({ message: "Invalid secret" });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await user.findOne({ email }).updateOne({ password: hashedPassword });
    await ForgotPassword.deleteOne({ email });
    return res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export default {
  signup,
  signin,
  signOut,
  verify,
  resendOtp,
  getAllUsers,
  getUsers,
  bulkInsert,
  checkAdminAuth,
  checkAuth,
  deleteUser,
  updateUser,
  createUser,
  changePassword,
  forgotPassword,
  forgotPasswordVerify,
  newPassword,
};