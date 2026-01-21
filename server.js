import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_NOW";

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

// =========================
// Schemas
// =========================
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["owner", "student"], required: true },
  enrolledClass: { type: String, default: null }
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true }
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true }
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  email: { type: String, required: true },
  className: { type: String, required: true },
  date: { type: String, required: true }, // YYYY-MM-DD
  status: { type: String, enum: ["Present", "Absent"], required: true }
}, { timestamps: true });

const MarksSchema = new mongoose.Schema({
  email: { type: String, required: true },
  subject: { type: String, required: true },
  marks: { type: Number, required: true }
}, { timestamps: true });

AttendanceSchema.index({ email: 1, date: 1 }, { unique: true });
MarksSchema.index({ email: 1, subject: 1 }, { unique: true });

const User = mongoose.model("User", UserSchema);
const ClassModel = mongoose.model("Class", ClassSchema);
const SubjectModel = mongoose.model("Subject", SubjectSchema);
const Attendance = mongoose.model("Attendance", AttendanceSchema);
const Marks = mongoose.model("Marks", MarksSchema);

// =========================
// Helpers
// =========================
function createToken(user) {
  return jwt.sign(
    { email: user.email, role: user.role, id: user._id },
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

// =========================
// Routes
// =========================
app.get("/", (req, res) => {
  res.send("✅ Secure Attendance Backend Running");
});

// ✅ Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ success: false, message: "User already exists" });

    const userCount = await User.countDocuments();
    const role = userCount === 0 ? "owner" : "student";

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      passwordHash,
      role
    });

    const token = createToken(user);

    res.json({
      success: true,
      message: "Signup successful ✅",
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        enrolledClass: user.enrolledClass
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.json({ success: false, message: "Invalid credentials" });

    const token = createToken(user);

    res.json({
      success: true,
      message: "Login successful ✅",
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        enrolledClass: user.enrolledClass
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Get current user
app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select("-passwordHash");
  res.json({ success: true, user });
});

// ✅ Owner: Add Student User
app.post("/owner/add-user", auth, onlyOwner, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ success: false, message: "User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      passwordHash,
      role: "student"
    });

    res.json({ success: true, message: "Student added ✅", user: { name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner: List users
app.get("/owner/users", auth, onlyOwner, async (req, res) => {
  const users = await User.find().select("-passwordHash").sort({ createdAt: -1 });
  res.json({ success: true, users });
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

// ✅ Student enroll class
app.post("/enroll", auth, async (req, res) => {
  try {
    const { className } = req.body;
    if (!className) return res.status(400).json({ success: false, message: "Missing className" });

    const updated = await User.findOneAndUpdate(
      { email: req.user.email },
      { enrolledClass: className },
      { new: true }
    ).select("-passwordHash");

    res.json({ success: true, message: "Enrolled ✅", user: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Owner mark attendance
app.post("/owner/attendance", auth, onlyOwner, async (req, res) => {
  try {
    const { email, className, status, date } = req.body;
    if (!email || !className || !status || !date)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const rec = await Attendance.create({ email, className, status, date });
    res.json({ success: true, message: "Attendance saved ✅", record: rec });
  } catch (err) {
    if (String(err.message).includes("duplicate key")) {
      return res.json({ success: false, message: "Attendance already marked for this student today" });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Student view attendance
app.get("/attendance", auth, async (req, res) => {
  const email = req.user.email;
  const records = await Attendance.find({ email }).sort({ createdAt: -1 });
  res.json({ success: true, records });
});

// ✅ Owner save marks
app.post("/owner/marks", auth, onlyOwner, async (req, res) => {
  try {
    const { email, subject, marks } = req.body;
    if (!email || !subject || marks === undefined)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const updated = await Marks.findOneAndUpdate(
      { email, subject },
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
  const email = req.user.email;
  const records = await Marks.find({ email }).sort({ createdAt: -1 });
  res.json({ success: true, records });
});

// ✅ Update profile
app.post("/profile", auth, async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Name required" });

    const update = { name };
    if (password && password.length >= 4) {
      update.passwordHash = await bcrypt.hash(password, 10);
    }

    const updated = await User.findOneAndUpdate(
      { email: req.user.email },
      update,
      { new: true }
    ).select("-passwordHash");

    res.json({ success: true, message: "Profile updated ✅", user: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("✅ Server running on port " + PORT));
