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

/* ✅ Mongo Connect */
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected to DB:", mongoose.connection.name))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

/* ===============================
   SCHEMAS
================================ */
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,

  role: { type: String, default: "student" }, // owner / staff / student
  enrolledClass: { type: String, default: null },

  // staff monitoring support
  monitorClass: { type: String, default: null },

  // profile fields
  gender: String,
  phone: String,
  dob: String,
  address: String,
  profilePic: String
}, { timestamps: true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String
}, { timestamps: true });

AttendanceSchema.index({ rollNumber: 1, className: 1, date: 1 }, { unique: true });

const MarksSchema = new mongoose.Schema({
  rollNumber: String,
  subject: String,
  marks: Number
}, { timestamps: true });

MarksSchema.index({ rollNumber: 1, subject: 1 }, { unique: true });

const ClassSchema = new mongoose.Schema({
  name: { type: String, unique: true }
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: { type: String, unique: true }
}, { timestamps: true });

/* ✅ Force collection names */
const User = mongoose.model("User", UserSchema, "users");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const Marks = mongoose.model("Marks", MarksSchema, "marks");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");
const SubjectModel = mongoose.model("Subject", SubjectSchema, "subjects");

/* ===============================
   HELPERS
================================ */
function safeUser(u){
  return {
    name: u.name,
    email: u.email,
    role: u.role,
    rollNumber: u.rollNumber,
    enrolledClass: u.enrolledClass,
    monitorClass: u.monitorClass || "",
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
  }catch{
    return res.status(401).json({ success:false, message:"Token expired/invalid" });
  }
}

function requireOwnerOrStaff(req, res, next){
  if(req.user.role === "owner" || req.user.role === "staff") return next();
  return res.status(403).json({ success:false, message:"Access denied" });
}

function requireOwner(req, res, next){
  if(req.user.role === "owner") return next();
  return res.status(403).json({ success:false, message:"Owner only" });
}

/* ===============================
   ROUTES
================================ */
app.get("/", (req, res) => {
  res.send("✅ ATTENDIFY Backend Running");
});

/* ✅ Debug DB */
app.get("/debug/db-check", async (req, res) => {
  try{
    res.json({
      success: true,
      connectedDB: mongoose.connection.name,
      collections: (await mongoose.connection.db.listCollections().toArray()).map(c => c.name),
      counts: {
        users: await User.countDocuments(),
        attendance: await Attendance.countDocuments(),
        marks: await Marks.countDocuments(),
        classes: await ClassModel.countDocuments(),
        subjects: await SubjectModel.countDocuments()
      }
    });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Signup */
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
      role,
      enrolledClass: null,
      monitorClass: null
    });

    const token = createToken(user);
    res.json({ success:true, token, user: safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Login */
app.post("/login", async (req, res) => {
  try{
    const { loginId, password } = req.body;
    if(!loginId || !password) return res.status(400).json({ success:false, message:"Fill all fields" });

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if(!user) return res.json({ success:false, message:"Invalid credentials" });
    if(!user.passwordHash) return res.json({ success:false, message:"User exists but password not set in DB" });

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

/* ✅ Enroll Student */
app.post("/enroll", auth, async (req, res) => {
  try{
    const { className } = req.body;
    if(!className) return res.status(400).json({ success:false, message:"Class required" });

    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.status(404).json({ success:false, message:"User not found" });

    user.enrolledClass = className;
    await user.save();

    res.json({ success:true, message:"Enrolled", user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Update Profile */
app.post("/profile", auth, async (req, res) => {
  try{
    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.status(404).json({ success:false, message:"User not found" });

    const {
      name, rollNumber, gender, phone, dob, address, password, profilePic
    } = req.body;

    if(name) user.name = name;
    if(rollNumber) user.rollNumber = rollNumber;
    if(gender !== undefined) user.gender = gender;
    if(phone !== undefined) user.phone = phone;
    if(dob !== undefined) user.dob = dob;
    if(address !== undefined) user.address = address;
    if(profilePic !== undefined) user.profilePic = profilePic;

    if(password){
      user.passwordHash = await bcrypt.hash(password, 10);
    }

    await user.save();
    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Attendance (student) */
app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success:true, records });
});

/* ✅ Marks (student) */
app.get("/marks", auth, async (req, res) => {
  const records = await Marks.find({ rollNumber: req.user.rollNumber }).sort({ createdAt: -1 });
  res.json({ success:true, records });
});

/* ✅ Get Classes */
app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success:true, classes });
});

/* ✅ Get Subjects */
app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name: 1 });
  res.json({ success:true, subjects });
});

/* ==========================================
   OWNER / STAFF FEATURES
========================================== */

/* ✅ Owner view all users */
app.get("/owner/users", auth, requireOwner, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json({ success:true, users: users.map(safeUser) });
});

/* ✅ Owner view one user profile */
app.get("/owner/user/:rollNumber", auth, requireOwner, async (req, res) => {
  const u = await User.findOne({ rollNumber: req.params.rollNumber });
  if(!u) return res.status(404).json({ success:false, message:"User not found" });
  res.json({ success:true, user: safeUser(u) });
});

/* ✅ Owner assign role + monitorClass */
app.post("/owner/user/:rollNumber/role", auth, requireOwner, async (req, res) => {
  try{
    const { role, monitorClass } = req.body;
    const u = await User.findOne({ rollNumber: req.params.rollNumber });
    if(!u) return res.status(404).json({ success:false, message:"User not found" });

    if(u.role === "owner") return res.json({ success:false, message:"Cannot change owner role" });

    if(!["student","staff"].includes(role)) {
      return res.status(400).json({ success:false, message:"Role must be student/staff" });
    }

    u.role = role;
    u.monitorClass = role === "staff" ? (monitorClass || null) : null;
    await u.save();

    res.json({ success:true, message:"Role updated", user: safeUser(u) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner add student */
app.post("/owner/add-user", auth, requireOwner, async (req, res) => {
  try{
    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password){
      return res.status(400).json({ success:false, message:"Fill all fields" });
    }

    const exists = await User.findOne({ $or: [{ email: email.toLowerCase() }, { rollNumber }] });
    if(exists) return res.json({ success:false, message:"User already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email: email.toLowerCase(),
      rollNumber,
      passwordHash,
      role: "student",
      enrolledClass: null,
      monitorClass: null
    });

    res.json({ success:true, message:"Student added", user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner add class */
app.post("/owner/class", auth, requireOwner, async (req, res) => {
  try{
    const { name } = req.body;
    if(!name) return res.status(400).json({ success:false, message:"Class name required" });

    await ClassModel.create({ name });
    res.json({ success:true, message:"Class added" });
  }catch(err){
    res.json({ success:false, message: err.message });
  }
});

/* ✅ Owner add subject */
app.post("/owner/subject", auth, requireOwner, async (req, res) => {
  try{
    const { name } = req.body;
    if(!name) return res.status(400).json({ success:false, message:"Subject name required" });

    await SubjectModel.create({ name });
    res.json({ success:true, message:"Subject added" });
  }catch(err){
    res.json({ success:false, message: err.message });
  }
});

/* ✅ Owner mark attendance (UPSERT) */
app.post("/owner/attendance", auth, requireOwnerOrStaff, async (req, res) => {
  try{
    const { rollNumber, className, date, status } = req.body;
    if(!rollNumber || !className || !date || !status){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    // staff can only mark their monitorClass
    if(req.user.role === "staff") {
      const staffUser = await User.findOne({ rollNumber: req.user.rollNumber });
      if(!staffUser?.monitorClass) return res.status(403).json({ success:false, message:"Staff not assigned to class" });
      if(staffUser.monitorClass !== className) return res.status(403).json({ success:false, message:"Not allowed for this class" });
    }

    await Attendance.findOneAndUpdate(
      { rollNumber, className, date },
      { rollNumber, className, date, status },
      { upsert: true, new: true }
    );

    res.json({ success:true, message:"Attendance saved" });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Get attendance list by class+date for admin button UI */
app.post("/owner/attendance/by-date", auth, requireOwnerOrStaff, async (req, res) => {
  try{
    const { className, date } = req.body;
    if(!className || !date) return res.status(400).json({ success:false, message:"Missing fields" });

    // staff restriction
    if(req.user.role === "staff") {
      const staffUser = await User.findOne({ rollNumber: req.user.rollNumber });
      if(!staffUser?.monitorClass) return res.status(403).json({ success:false, message:"Staff not assigned to class" });
      if(staffUser.monitorClass !== className) return res.status(403).json({ success:false, message:"Not allowed for this class" });
    }

    const records = await Attendance.find({ className, date });
    res.json({ success:true, records });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Owner save marks (UPSERT) */
app.post("/owner/marks", auth, requireOwner, async (req, res) => {
  try{
    const { rollNumber, subject, marks } = req.body;
    if(!rollNumber || !subject || marks === undefined){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    await Marks.findOneAndUpdate(
      { rollNumber, subject },
      { rollNumber, subject, marks },
      { upsert: true, new: true }
    );

    res.json({ success:true, message:"Marks saved" });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Start */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
