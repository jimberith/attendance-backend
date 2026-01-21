import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

// ✅ Models
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: String,
  enrolledClass: String
});

const AttendanceSchema = new mongoose.Schema({
  email: String,
  className: String,
  date: String,
  status: String
});

const MarksSchema = new mongoose.Schema({
  email: String,
  subject: String,
  marks: Number
});

const User = mongoose.model("User", UserSchema);
const Attendance = mongoose.model("Attendance", AttendanceSchema);
const Marks = mongoose.model("Marks", MarksSchema);

// ✅ Test route
app.get("/", (req, res) => {
  res.send("✅ Attendance backend is running");
});

// ✅ Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    const userCount = await User.countDocuments();
    const role = userCount === 0 ? "owner" : "student";

    const user = await User.create({
      name,
      email,
      password,
      role,
      enrolledClass: null
    });

    res.json({ success: true, message: "Signup successful ✅", user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    res.json({ success: true, message: "Login successful ✅", user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Save Attendance
app.post("/attendance", async (req, res) => {
  try {
    const { email, className, date, status } = req.body;

    const record = await Attendance.create({ email, className, date, status });
    res.json({ success: true, message: "Attendance saved ✅", record });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Get Attendance
app.get("/attendance/:email", async (req, res) => {
  try {
    const records = await Attendance.find({ email: req.params.email }).sort({ _id: -1 });
    res.json({ success: true, records });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Save Marks
app.post("/marks", async (req, res) => {
  try {
    const { email, subject, marks } = req.body;

    const existing = await Marks.findOne({ email, subject });
    if (existing) {
      existing.marks = marks;
      await existing.save();
      return res.json({ success: true, message: "Marks updated ✅", record: existing });
    }

    const record = await Marks.create({ email, subject, marks });
    res.json({ success: true, message: "Marks saved ✅", record });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Get Marks
app.get("/marks/:email", async (req, res) => {
  try {
    const records = await Marks.find({ email: req.params.email });
    res.json({ success: true, records });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("✅ Server running on port " + PORT));
