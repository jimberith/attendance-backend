import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();

/* ✅ CORS */
app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

app.use(express.json({ limit: "8mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

/* ✅ MongoDB Connect */
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

/* ===============================
   Schemas (matches existing data)
================================ */
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  rollNumber: { type: String, unique: true },

  // old db might store "password" OR new db stores "passwordHash"
  passwordHash: String,

  role: { type: String, default: "student" },
  enrolledClass: { type: String, default: null },

  gender: { type: String, default: "" },
  phone: { type: String, default: "" },
  dob: { type: String, default: "" },
  address: { type: String, default: "" },
  profilePic: { type: String, default: "" }
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({
  name: { type: String, unique: true }
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: { type: String, unique: true }
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String
}, { timestamps: true });

const MarksSchema = new mongoose.Schema({
  rollNumber: String,
  subject: String,
  marks: Number
}, { timestamps: true });

const SettingsSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: Object
}, { timestamps: true });

/* ✅ IMPORTANT: Force collection names to match your old data */
const User = mongoose.model("User", UserSchema, "users");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");
const SubjectModel = mongoose.model("Subject", SubjectSchema, "subjects");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const Marks = mongoose.model("Marks", MarksSchema, "marks");
const Settings = mongoose.model("Settings", SettingsSchema, "settings");

/* ===============================
   Helpers
================================ */
function safeUser(u){
  return {
    name: u.name,
    role: u.role,
    rollNumber: u.rollNumber,
    enrolledClass: u.enrolledClass,
    gender: u.gender || "",
    phone: u.phone || "",
    dob: u.dob || "",
    address: u.address || "",
    profilePic: u.profilePic || ""
  };
}

function createToken(u){
  return jwt.sign(
    { id: u._id, role: u.role, rollNumber: u.rollNumber },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next){
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({ success:false, message:"Missing token" });

  const token = header.split(" ")[1];
  if(!token) return res.status(401).json({ success:false, message:"Invalid token" });

  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(err){
    return res.status(401).json({ success:false, message:"Token expired/invalid" });
  }
}

function onlyOwner(req, res, next){
  if(req.user.role !== "owner"){
    return res.status(403).json({ success:false, message:"Owner access only" });
  }
  next();
}

/* ===============================
   Routes
================================ */

/* ✅ Test route */
app.get("/", (req, res) => {
  res.send("✅ ATTENDIFY Backend Running");
});

/* ✅ Debug existing DB data counts */
app.get("/debug/db-check", async (req, res) => {
  try{
    res.json({
      success: true,
      users: await User.countDocuments(),
      classes: await ClassModel.countDocuments(),
      subjects: await SubjectModel.countDocuments(),
      attendance: await Attendance.countDocuments(),
      marks: await Marks.countDocuments(),
      settings: await Settings.countDocuments()
    });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Email exists check */
app.post("/auth/check-email", async (req, res) => {
  try{
    const { email } = req.body;
    if(!email) return res.status(400).json({ success:false, message:"Email required" });

    const u = await User.findOne({ email: email.toLowerCase() });
    res.json({ success:true, exists: !!u });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Signup (first user becomes owner) */
app.post("/signup", async (req, res) => {
  try{
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
    }

    const emailExists = await User.findOne({ email: email.toLowerCase() });
    if(emailExists) return res.json({ success:false, message:"Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if(rollExists) return res.json({ success:false, message:"Roll number already exists" });

    const count = await User.countDocuments();
    const role = count === 0 ? "owner" : "student";

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      rollNumber,
      passwordHash,
      role
    });

    // default range settings
    const range = await Settings.findOne({ key: "attendanceRange" });
    if(!range){
      await Settings.create({ key: "attendanceRange", value: { start:"", end:"" } });
    }

    const token = createToken(user);

    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Login (Name/Email/Roll) */
app.post("/login", async (req, res) => {
  try{
    const { loginId, password } = req.body;
    if(!loginId || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
    }

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if(!user) return res.json({ success:false, message:"Invalid credentials" });

    // IMPORTANT: Existing old db users might have NO passwordHash stored
    if(!user.passwordHash){
      return res.json({
        success:false,
        message:"User exists in DB but password not set. Reset password using profile update."
      });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.json({ success:false, message:"Invalid credentials" });

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Me */
app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  if(!user) return res.status(404).json({ success:false, message:"User not found" });
  res.json({ success:true, user: safeUser(user) });
});

/* ✅ Update profile (also sets passwordHash if needed) */
app.post("/profile", auth, async (req, res) => {
  try{
    const {
      name, rollNumber, gender, phone, dob, address,
      password, profilePic
    } = req.body;

    if(!name || !rollNumber){
      return res.status(400).json({ success:false, message:"Name + Roll required" });
    }

    const existingRoll = await User.findOne({ rollNumber });
    if(existingRoll && existingRoll.rollNumber !== req.user.rollNumber){
      return res.json({ success:false, message:"Roll number already exists" });
    }

    const update = {
      name,
      rollNumber,
      gender: gender ?? "",
      phone: phone ?? "",
      dob: dob ?? "",
      address: address ?? ""
    };

    if(profilePic) update.profilePic = profilePic;

    if(password && password.length >= 4){
      update.passwordHash = await bcrypt.hash(password, 10);
    }

    const updated = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      update,
      { new: true }
    );

    res.json({ success:true, user: safeUser(updated) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Enroll */
app.post("/enroll", auth, async (req, res) => {
  try{
    const { className } = req.body;
    if(!className) return res.status(400).json({ success:false, message:"Missing className" });

    const updated = await User.findOneAndUpdate(
      { rollNumber: req.user.rollNumber },
      { enrolledClass: className },
      { new: true }
    );

    res.json({ success:true, user: safeUser(updated) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner: add user */
app.post("/owner/add-user", auth, onlyOwner, async (req, res) => {
  try{
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
    }

    const emailExists = await User.findOne({ email: email.toLowerCase() });
    if(emailExists) return res.json({ success:false, message:"Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if(rollExists) return res.json({ success:false, message:"Roll number already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      rollNumber,
      passwordHash,
      role: "student"
    });

    res.json({ success:true, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner: list users */
app.get("/owner/users", auth, onlyOwner, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json({ success:true, users: users.map(safeUser) });
});

/* ✅ Owner: add class */
app.post("/owner/class", auth, onlyOwner, async (req, res) => {
  try{
    const { name } = req.body;
    if(!name) return res.status(400).json({ success:false, message:"Missing class name" });

    const c = await ClassModel.create({ name });
    res.json({ success:true, class: c });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner: add subject */
app.post("/owner/subject", auth, onlyOwner, async (req, res) => {
  try{
    const { name } = req.body;
    if(!name) return res.status(400).json({ success:false, message:"Missing subject name" });

    const s = await SubjectModel.create({ name });
    res.json({ success:true, subject: s });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Get classes */
app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success:true, classes });
});

/* ✅ Get subjects */
app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name: 1 });
  res.json({ success:true, subjects });
});

/* ✅ Owner: mark attendance */
app.post("/owner/attendance", auth, onlyOwner, async (req, res) => {
  try{
    const { rollNumber, className, status, date } = req.body;
    if(!rollNumber || !className || !status || !date){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    // Upsert: replace if already exists
    const record = await Attendance.findOneAndUpdate(
      { rollNumber, date },
      { rollNumber, className, status, date },
      { upsert: true, new: true }
    );

    res.json({ success:true, record });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Student: view attendance */
app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success:true, records });
});

/* ✅ Owner: save marks */
app.post("/owner/marks", auth, onlyOwner, async (req, res) => {
  try{
    const { rollNumber, subject, marks } = req.body;
    if(!rollNumber || !subject || marks === undefined){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    const record = await Marks.findOneAndUpdate(
      { rollNumber, subject },
      { rollNumber, subject, marks },
      { upsert: true, new: true }
    );

    res.json({ success:true, record });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Student: view marks */
app.get("/marks", auth, async (req, res) => {
  const records = await Marks.find({ rollNumber: req.user.rollNumber }).sort({ createdAt: -1 });
  res.json({ success:true, records });
});

/* ✅ Owner range */
app.get("/owner/range", auth, onlyOwner, async (req, res) => {
  const r = await Settings.findOne({ key:"attendanceRange" });
  res.json({ success:true, range: r?.value || { start:"", end:"" } });
});

app.post("/owner/range", auth, onlyOwner, async (req, res) => {
  try{
    const { start, end } = req.body;

    const saved = await Settings.findOneAndUpdate(
      { key:"attendanceRange" },
      { value:{ start: start || "", end: end || "" } },
      { upsert: true, new: true }
    );

    res.json({ success:true, range: saved.value });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Start server */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port " + PORT));
