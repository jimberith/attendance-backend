import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" })); // for profile image base64

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_NOW";

// ✅ Mongo connect
mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

// =========================
// Schemas
// =========================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  rollNumber: { type: String, unique: true, required: true },

  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["owner", "student"], required: true },

  enrolledClass: { type: String, default: null },

  // Profile fields
  gender: { type: String, enum: ["Male", "Female", "Other", ""], default: "" },
  phone: { type: String, default: "" },
  dob: { type: String, default: "" }, // YYYY-MM-DD
  address: { type: String, default: "" },
  profilePic: { type: String, default: "" } // base64
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true }
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true }
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: { type: String, required: true },
  className: { type: String, required: true },
  date: { type: String, required: true }, // YYYY-MM-DD
  status: { type: String, enum: ["Present", "Absent", "On Duty (O/D)", "Leave"], required: true }
}, { timestamps: true });

const MarksSchema = new mongoose.Schema({
  rollNumber: { type: String, required: true },
  subject: { type: String, required: true },
  marks: { type: Number, required: true }
}, { timestamps: true });

// one attendance per day per roll
AttendanceSchema.index({ rollNumber: 1, date: 1 }, { unique: true });
// one marks per subject per roll
MarksSchema.index({ rollNumber: 1, subject: 1 }, { unique: true });

// Admin settings
const SettingsSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: { type: Object, required: true }
}, { timestamps: true });

const User = mongoose.model("User", UserSchema);
const ClassModel = mongoose.model("Class", ClassSchema);
const SubjectModel = mongoose.model("Subject", SubjectSchema);
const Attendance = mongoose.model("Attendance", AttendanceSchema);
const Marks = mongoose.model("Marks", MarksSchema);
const Settings = mongoose.model("Settings", SettingsSchema);

// =========================
// Helpers
// =========================
function createToken(user) {
  return jwt.sign(
    { id: user._id, role: user.role, rollNumber: user.rollNumber },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success: false, message: "Missing token" });

  const token = header.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Invalid token format" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Token expired/invalid" });
  }
}

function onlyOwner(req, res, next) {
  if (req.user.role !== "owner") {
    return res.status(403).json({ success: false, message: "Owner access only" });
  }
  next();
}

function safeUser(user) {
  return {
    name: user.name,
    role: user.role,
    rollNumber: user.rollNumber,
    enrolledClass: user.enrolledClass,
    gender: user.gender,
    phone: user.phone,
    dob: user.dob,
    address: user.address,
    profilePic: user.profilePic
  };
}

// =========================
// Routes
// =========================
app.get("/", (req, res) => {
  res.send("✅ ATTENDIFY Backend Running");
});

// ✅ Signup (needs name + email + roll + password)
app.post("/signup", async (req, res) => {
  try {
    const { name, email, rollNumber, password } = req.body;
    if (!name || !email || !rollNumber || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const emailExists = await User.findOne({ email });
    if (emailExists) return res.json({ success: false, message: "Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if (rollExists) return res.json({ success: false, message: "Roll Number already exists" });

    const userCount = await User.countDocuments();
    const role = userCount === 0 ? "owner" : "student";

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      rollNumber,
      passwordHash,
      role
    });

    // Create default date range settings (once)
    const existing = await Settings.findOne({ key: "attendanceRange" });
    if (!existing) {
      await Settings.create({
        key: "attendanceRange",
        value: { start: "", end: "" }
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      message: "Signup successful ✅",
      token,
      user: safeUser(user)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Login (loginId: name/email/rollNumber + password)
app.post("/login", async (req, res) => {
  try {
    const { loginId, password } = req.body;
    if (!loginId || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if (!user) return res.json({ success: false, message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Invalid credentials" });

    const token = createToken(user);

    res.json({
      success: true,
      message: "Login successful ✅",
      token,
      user: safeUser(user)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Get current user
app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  if (!user) return res.status(404).json({ success: false, message: "User not found" });
  res.json({ success: true, user: safeUser(user) });
});

// ✅ Update profile
app.post("/profile", auth, async (req, res) => {
  try {
    const { name, rollNumber, gender, phone, dob, address, password, profilePic } = req.body;

    if (!name || !rollNumber) {
      return res.status(400).json({ success: false, message: "Name + Roll required" });
    }

    // ensure new roll is unique if changed
    const existing = await User.findOne({ rollNumber });
    if (existing && existing.rollNumber !== req.user.rollNumber) {
      return res.json({ success: false, message: "Roll Number already used" });
    }

    const update = {
      name,
      rollNumber,
      gender: gender ?? "",
      phone: phone ?? "",
      dob: dob ?? "",
      address: address ?? ""
    };

    if (profilePic) update.profilePic = profilePic;

    if (password && password.length >= 4) {
      update.passwordHash = await bcrypt.hash(password, 10);
    }

    const updated = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      update,
      { new: true }
    );

    res.json({ success: true, message: "Profile updated ✅", user: safeUser(updated) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner: Add Student
app.post("/owner/add-user", auth, onlyOwner, async (req, res) => {
  try {
    const { name, email, rollNumber, password } = req.body;

    if (!name || !email || !rollNumber || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const emailExists = await User.findOne({ email });
    if (emailExists) return res.json({ success: false, message: "Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if (rollExists) return res.json({ success: false, message: "Roll Number already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      rollNumber,
      passwordHash,
      role: "student"
    });

    res.json({
      success: true,
      message: "Student added ✅",
      user: safeUser(user)
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner: List Users (no email sent)
app.get("/owner/users", auth, onlyOwner, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json({
    success: true,
    users: users.map(u => safeUser(u))
  });
});

// ✅ Owner: Add class
app.post("/owner/class", auth, onlyOwner, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Missing class name" });

    const c = await ClassModel.create({ name });
    res.json({ success: true, message: "Class added ✅", class: c });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner: Add subject
app.post("/owner/subject", auth, onlyOwner, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Missing subject name" });

    const s = await SubjectModel.create({ name });
    res.json({ success: true, message: "Subject added ✅", subject: s });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Get classes
app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success: true, classes });
});

// ✅ Get subjects
app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name: 1 });
  res.json({ success: true, subjects });
});

// ✅ Student enroll
app.post("/enroll", auth, async (req, res) => {
  try {
    const { className } = req.body;
    if (!className) return res.status(400).json({ success: false, message: "Missing className" });

    const updated = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      { enrolledClass: className },
      { new: true }
    );

    res.json({ success: true, message: "Enrolled ✅", user: safeUser(updated) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner mark attendance
app.post("/owner/attendance", auth, onlyOwner, async (req, res) => {
  try {
    const { rollNumber, className, status, date } = req.body;

    if (!rollNumber || !className || !status || !date)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const rec = await Attendance.create({ rollNumber, className, status, date });
    res.json({ success: true, message: "Attendance saved ✅", record: rec });
  } catch (err) {
    if (String(err.message).includes("duplicate key")) {
      return res.json({ success: false, message: "Attendance already marked for today" });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Student view attendance
app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success: true, records });
});

// ✅ Owner save marks
app.post("/owner/marks", auth, onlyOwner, async (req, res) => {
  try {
    const { rollNumber, subject, marks } = req.body;
    if (!rollNumber || !subject || marks === undefined)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const updated = await Marks.findOneAndUpdate(
      { rollNumber, subject },
      { marks },
      { upsert: true, new: true }
    );

    res.json({ success: true, message: "Marks saved ✅", record: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Student view marks
app.get("/marks", auth, async (req, res) => {
  const records = await Marks.find({ rollNumber: req.user.rollNumber }).sort({ createdAt: -1 });
  res.json({ success: true, records });
});

// ✅ Owner: Get attendance percentage range
app.get("/owner/range", auth, onlyOwner, async (req, res) => {
  const s = await Settings.findOne({ key: "attendanceRange" });
  res.json({ success: true, range: s?.value || { start: "", end: "" } });
});

// ✅ Owner: Set attendance percentage range
app.post("/owner/range", auth, onlyOwner, async (req, res) => {
  const { start, end } = req.body;
  const updated = await Settings.findOneAndUpdate(
    { key: "attendanceRange" },
    { value: { start: start || "", end: end || "" } },
    { upsert: true, new: true }
  );
  res.json({ success: true, message: "Range saved ✅", range: updated.value });
});

// ✅ Start
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port " + PORT));
