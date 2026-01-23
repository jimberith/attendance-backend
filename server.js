import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import PDFDocument from "pdfkit";
import twilio from "twilio";

dotenv.config();
const app = express();

/* ✅ CORS */
app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json({ limit: "12mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected:", mongoose.connection.name))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

/* ===============================
   SCHEMAS
================================ */
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,

  // roles: owner | staff | student
  role: { type: String, default: "student" },

  enrolledClass: { type: String, default: null },

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

const ResultSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  subject: String,

  internal: { type: Number, default: 0 },     // 0-30
  assessment: { type: Number, default: 0 },   // 0-20
  exam: { type: Number, default: 0 },         // 0-50
  total: { type: Number, default: 0 }         // /100
}, { timestamps: true });

const ClassSchema = new mongoose.Schema({
  name: String
}, { timestamps: true });

const SubjectSchema = new mongoose.Schema({
  name: String
}, { timestamps: true });

const StaffPermissionSchema = new mongoose.Schema({
  staffRollNumber: String,
  className: String
}, { timestamps: true });

/* ✅ Force collection names */
const User = mongoose.model("User", UserSchema, "users");
const Attendance = mongoose.model("Attendance", AttendanceSchema, "attendance");
const Result = mongoose.model("Result", ResultSchema, "results");
const ClassModel = mongoose.model("Class", ClassSchema, "classes");
const SubjectModel = mongoose.model("Subject", SubjectSchema, "subjects");
const StaffPermission = mongoose.model("StaffPermission", StaffPermissionSchema, "staff_permissions");

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

function ownerOnly(req, res, next){
  if(req.user.role !== "owner") return res.status(403).json({ success:false, message:"Owner only" });
  next();
}

async function staffCanAccessClass(reqUser, className){
  if(reqUser.role === "owner") return true;
  if(reqUser.role !== "staff") return false;

  const allow = await StaffPermission.findOne({ staffRollNumber: reqUser.rollNumber, className });
  return !!allow;
}

/* ===============================
   MAIL + WHATSAPP SETUP
================================ */
function getMailer(){
  if(!process.env.EMAIL_USER || !process.env.EMAIL_APP_PASS) return null;
  return nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_APP_PASS }
  });
}

async function sendMail(to, subject, html){
  try{
    const mailer = getMailer();
    if(!mailer) return { success:false, message:"Mailer not configured" };

    await mailer.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      html
    });
    return { success:true };
  }catch(err){
    return { success:false, message: err.message };
  }
}

async function sendWhatsApp(toPhone, text){
  try{
    if(!process.env.TWILIO_SID || !process.env.TWILIO_AUTH || !process.env.TWILIO_WHATSAPP_FROM){
      return { success:false, message:"WhatsApp not configured" };
    }

    const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

    const to = toPhone.startsWith("whatsapp:") ? toPhone : `whatsapp:${toPhone}`;

    await client.messages.create({
      from: process.env.TWILIO_WHATSAPP_FROM,
      to,
      body: text
    });

    return { success:true };
  }catch(err){
    return { success:false, message: err.message };
  }
}

/* ===============================
   ROUTES
================================ */
app.get("/", (req, res) => res.send("✅ ATTENDIFY Backend Running"));
app.get("/health", (req,res)=>res.json({success:true, db: mongoose.connection.readyState}));

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
      enrolledClass: null
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

/* ✅ Profile update */
app.post("/profile", auth, async (req, res) => {
  try{
    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.status(404).json({ success:false, message:"User not found" });

    const { name, rollNumber, gender, phone, dob, address, profilePic, password } = req.body;

    if(name) user.name = name;
    if(rollNumber) user.rollNumber = rollNumber;

    if(gender !== undefined) user.gender = gender;
    if(phone !== undefined) user.phone = phone;
    if(dob !== undefined) user.dob = dob;
    if(address !== undefined) user.address = address;
    if(profilePic) user.profilePic = profilePic;

    if(password && password.trim().length >= 4){
      user.passwordHash = await bcrypt.hash(password.trim(), 10);
    }

    await user.save();
    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Enroll */
app.post("/enroll", auth, async (req, res) => {
  try{
    const { className } = req.body;
    if(!className) return res.status(400).json({ success:false, message:"Missing className" });

    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    user.enrolledClass = className;
    await user.save();

    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Student Attendance */
app.get("/attendance", auth, async (req, res) => {
  const records = await Attendance.find({ rollNumber: req.user.rollNumber }).sort({ date: -1 });
  res.json({ success:true, records });
});

/* ✅ Student Results */
app.get("/results", auth, async (req, res) => {
  const records = await Result.find({ rollNumber: req.user.rollNumber }).sort({ createdAt: -1 });
  res.json({ success:true, records });
});

/* ✅ CGPA */
app.get("/cgpa", auth, async (req, res) => {
  const results = await Result.find({ rollNumber: req.user.rollNumber });
  if(results.length === 0) return res.json({ success:true, cgpa: 0 });

  function gp(total){
    if(total >= 90) return 10;
    if(total >= 80) return 9;
    if(total >= 70) return 8;
    if(total >= 60) return 7;
    if(total >= 50) return 6;
    if(total >= 40) return 5;
    return 0;
  }

  const avg = results.reduce((sum,r)=>sum+gp(r.total),0)/results.length;
  res.json({ success:true, cgpa: avg });
});

/* ✅ PDF Marksheet */
app.get("/marksheet/pdf", auth, async (req, res) => {
  try{
    const user = await User.findOne({ rollNumber: req.user.rollNumber });
    if(!user) return res.status(404).send("User not found");

    const results = await Result.find({ rollNumber: req.user.rollNumber }).sort({ subject: 1 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename="Marksheet_${user.rollNumber}.pdf"`);

    const doc = new PDFDocument({ margin: 40 });
    doc.pipe(res);

    doc.fontSize(20).text("ATTENDIFY - MARKSHEET", { align: "center" });
    doc.moveDown();

    doc.fontSize(12).text(`Name: ${user.name}`);
    doc.text(`Roll Number: ${user.rollNumber}`);
    doc.text(`Class: ${user.enrolledClass || "-"}`);
    doc.text(`Email: ${user.email}`);
    doc.moveDown();

    doc.fontSize(14).text("Subject Wise Marks", { underline: true });
    doc.moveDown(0.5);

    doc.fontSize(11).text("Subject", 40, doc.y, { continued: true });
    doc.text("Internal", 220, doc.y, { continued: true });
    doc.text("Assessment", 300, doc.y, { continued: true });
    doc.text("Exam", 410, doc.y, { continued: true });
    doc.text("Total", 480, doc.y);

    doc.moveDown(0.3);
    doc.text("------------------------------------------------------------");

    results.forEach(r => {
      doc.text(r.subject, 40, doc.y, { continued: true });
      doc.text(String(r.internal), 220, doc.y, { continued: true });
      doc.text(String(r.assessment), 320, doc.y, { continued: true });
      doc.text(String(r.exam), 420, doc.y, { continued: true });
      doc.text(String(r.total), 490, doc.y);
    });

    doc.end();
  }catch(err){
    res.status(500).send(err.message);
  }
});

/* ✅ Classes + Subjects */
app.get("/classes", auth, async (req, res) => {
  const classes = await ClassModel.find().sort({ name: 1 });
  res.json({ success:true, classes });
});

app.get("/subjects", auth, async (req, res) => {
  const subjects = await SubjectModel.find().sort({ name: 1 });
  res.json({ success:true, subjects });
});

/* ===============================
   ADMIN (OWNER/STAFF)
================================ */
app.get("/owner/users", auth, async (req, res) => {
  if(req.user.role !== "owner" && req.user.role !== "staff"){
    return res.status(403).json({ success:false, message:"Admin only" });
  }
  const users = await User.find().sort({ createdAt: -1 });
  res.json({ success:true, users: users.map(safeUser) });
});

/* ✅ OWNER only role update */
app.post("/owner/set-role", auth, ownerOnly, async (req, res) => {
  try{
    const { rollNumber, role } = req.body;
    if(!rollNumber || !role) return res.status(400).json({ success:false, message:"Missing fields" });

    if(!["student","staff"].includes(role)){
      return res.status(400).json({ success:false, message:"Only student/staff allowed" });
    }

    const user = await User.findOne({ rollNumber });
    if(!user) return res.status(404).json({ success:false, message:"User not found" });

    user.role = role;
    await user.save();
    res.json({ success:true, user: safeUser(user) });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ OWNER gives staff-class permission */
app.post("/owner/staff-permission", auth, ownerOnly, async (req, res) => {
  try{
    const { staffRollNumber, className } = req.body;
    if(!staffRollNumber || !className){
      return res.status(400).json({ success:false, message:"Missing staff/class" });
    }

    const staff = await User.findOne({ rollNumber: staffRollNumber });
    if(!staff || staff.role !== "staff"){
      return res.status(400).json({ success:false, message:"User not staff" });
    }

    const exists = await StaffPermission.findOne({ staffRollNumber, className });
    if(exists) return res.json({ success:true, message:"Already permitted" });

    await StaffPermission.create({ staffRollNumber, className });
    res.json({ success:true, message:"Permission granted" });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Attendance by date */
app.post("/owner/attendance/by-date", auth, async (req, res) => {
  try{
    const { className, date } = req.body;
    if(!className || !date) return res.status(400).json({ success:false, message:"Missing fields" });

    const ok = await staffCanAccessClass(req.user, className);
    if(!ok) return res.status(403).json({ success:false, message:"No permission for class" });

    const records = await Attendance.find({ className, date });
    res.json({ success:true, records });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Attendance mark */
app.post("/owner/attendance", auth, async (req, res) => {
  try{
    const { rollNumber, className, status, date } = req.body;
    if(!rollNumber || !className || !status || !date){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    const ok = await staffCanAccessClass(req.user, className);
    if(!ok) return res.status(403).json({ success:false, message:"No permission for class" });

    await Attendance.findOneAndUpdate(
      { rollNumber, date },
      { rollNumber, className, status, date },
      { upsert: true, new: true }
    );

    res.json({ success:true, message:"Saved" });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Marks save + notify */
app.post("/owner/marks", auth, async (req, res) => {
  try{
    const { rollNumber, className, subject, internal, assessment, exam } = req.body;
    if(!rollNumber || !className || !subject){
      return res.status(400).json({ success:false, message:"Missing fields" });
    }

    const ok = await staffCanAccessClass(req.user, className);
    if(!ok) return res.status(403).json({ success:false, message:"No permission for class" });

    const i = Number(internal || 0);
    const a = Number(assessment || 0);
    const e = Number(exam || 0);
    const total = i + a + e;

    const record = await Result.findOneAndUpdate(
      { rollNumber, subject },
      { rollNumber, className, subject, internal: i, assessment: a, exam: e, total },
      { upsert: true, new: true }
    );

    const student = await User.findOne({ rollNumber });
    if(student){
      // Email
      await sendMail(
        student.email,
        `ATTENDIFY: Marks Updated (${subject})`,
        `
          <h2>ATTENDIFY - Marks Updated</h2>
          <p>Hello <b>${student.name}</b>,</p>
          <p>Your marks were updated:</p>
          <ul>
            <li>Subject: <b>${subject}</b></li>
            <li>Internal: <b>${i}</b>/30</li>
            <li>Assessment: <b>${a}</b>/20</li>
            <li>Exam: <b>${e}</b>/50</li>
            <li>Total: <b>${total}</b>/100</li>
          </ul>
          <p>Class: <b>${className}</b></p>
        `
      );

      // WhatsApp (optional)
      if(student.phone){
        await sendWhatsApp(
          student.phone,
          `ATTENDIFY ✅ Marks Updated\n${student.name} (${student.rollNumber})\n${subject}\nInternal: ${i}/30\nAssessment: ${a}/20\nExam: ${e}/50\nTotal: ${total}/100`
        );
      }
    }

    res.json({ success:true, record });
  }catch(err){
    res.status(500).json({ success:false, message: err.message });
  }
});

/* ✅ Start */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
