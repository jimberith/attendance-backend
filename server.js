import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
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
app.use(express.json({ limit: "10mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const MONGO_URI = process.env.MONGO_URI;

/* ✅ MongoDB */
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => console.log("✅ MongoDB Connected:", mongoose.connection.name))
  .catch(err => console.log("❌ MongoDB Error:", err.message));

/* ===============================
   MAIL (Nodemailer Gmail)
================================ */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASS
  }
});

async function sendMail(to, subject, text){
  if (!to) return;
  await transporter.sendMail({
    from: `"ATTENDIFY" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    text
  });
}

/* ===============================
   WHATSAPP (Twilio)
================================ */
let twilioClient = null;
if (process.env.TWILIO_SID && process.env.TWILIO_AUTH) {
  twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);
}

async function sendWhatsApp(toPhone, message){
  if(!twilioClient) return;
  if(!toPhone) return;
  try{
    await twilioClient.messages.create({
      from: process.env.TWILIO_WHATSAPP,
      to: `whatsapp:${toPhone}`,
      body: message
    });
  }catch(err){
    console.log("❌ WhatsApp error:", err.message);
  }
}

/* ===============================
   SCHEMAS
================================ */
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,

  role: { type:String, default:"student" }, // owner | staff | student
  enrolledClass: String,

  monitorClasses: { type:[String], default:[] }, // staff allowed classes

  gender: String,
  phone: String,
  dob: String,
  address: String,
  profilePic: String,

  emailVerified: { type:Boolean, default:false },
  otpHash: String,
  otpExpiry: String
}, { timestamps:true });

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String
}, { timestamps:true });

const MarksSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  subject: String,

  internal: { type:Number, default:0 },   // 0-30
  assessment: { type:Number, default:0 }, // 0-20
  exam: { type:Number, default:0 },       // 0-50
  total: { type:Number, default:0 },      // 0-100
  gradePoint: { type:Number, default:0 }
}, { timestamps:true });

const ClassSchema = new mongoose.Schema({ name:String }, { timestamps:true });
const SubjectSchema = new mongoose.Schema({ name:String }, { timestamps:true });

/* ✅ Force collections */
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

    monitorClasses: u.monitorClasses || [],

    gender: u.gender || "",
    phone: u.phone || "",
    dob: u.dob || "",
    address: u.address || "",
    profilePic: u.profilePic || "",
    emailVerified: u.emailVerified || false
  };
}

function createToken(u){
  return jwt.sign(
    { id:u._id, role:u.role, rollNumber:u.rollNumber },
    JWT_SECRET,
    { expiresIn:"7d" }
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

function isValidEmail(email){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOTP(){
  return String(Math.floor(100000 + Math.random() * 900000));
}
function hashOTP(otp){
  return crypto.createHash("sha256").update(otp).digest("hex");
}

function calcGradePoint(total){
  if(total >= 90) return 10;
  if(total >= 80) return 9;
  if(total >= 70) return 8;
  if(total >= 60) return 7;
  if(total >= 50) return 6;
  return 0;
}

/* ===============================
   ROUTES
================================ */
app.get("/", (req, res) => res.send("✅ ATTENDIFY Backend Running"));

/* ✅ Signup (OTP sent) */
app.post("/signup", async (req,res)=>{
  try{
    const { name, email, rollNumber, password } = req.body;

    if(!name || !email || !rollNumber || !password){
      return res.json({ success:false, message:"Fill all fields" });
    }

    const cleanEmail = email.trim().toLowerCase();
    if(!isValidEmail(cleanEmail)){
      return res.json({ success:false, message:"Invalid email format" });
    }

    const emailExists = await User.findOne({ email: cleanEmail });
    if(emailExists) return res.json({ success:false, message:"Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if(rollExists) return res.json({ success:false, message:"Roll number already exists" });

    const count = await User.countDocuments();
    const role = count === 0 ? "owner" : "student";

    const passwordHash = await bcrypt.hash(password, 10);

    const otp = generateOTP();
    const otpHash = hashOTP(otp);
    const otpExpiry = new Date(Date.now() + 10*60*1000).toISOString();

    await User.create({
      name,
      email: cleanEmail,
      rollNumber,
      passwordHash,
      role,
      enrolledClass: null,
      monitorClasses: [],
      emailVerified:false,
      otpHash,
      otpExpiry
    });

    await sendMail(
      cleanEmail,
      "ATTENDIFY Email Verification OTP",
      `Hello ${name},

Your OTP is: ${otp}
Expires in 10 minutes.

- ATTENDIFY`
    );

    res.json({ success:true, message:"OTP sent to email ✅", rollNumber });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Verify OTP */
app.post("/verify-email", async (req,res)=>{
  try{
    const { rollNumber, otp } = req.body;
    if(!rollNumber || !otp) return res.json({ success:false, message:"Roll + OTP required" });

    const user = await User.findOne({ rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    if(user.emailVerified){
      const token = createToken(user);
      return res.json({ success:true, token, user:safeUser(user) });
    }

    if(new Date() > new Date(user.otpExpiry)){
      return res.json({ success:false, message:"OTP expired. Resend OTP." });
    }

    if(hashOTP(String(otp).trim()) !== user.otpHash){
      return res.json({ success:false, message:"Invalid OTP" });
    }

    user.emailVerified = true;
    user.otpHash = "";
    user.otpExpiry = "";
    await user.save();

    const token = createToken(user);
    res.json({ success:true, message:"Verified ✅", token, user:safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Resend OTP */
app.post("/resend-otp", async (req,res)=>{
  try{
    const { rollNumber } = req.body;
    if(!rollNumber) return res.json({ success:false, message:"Roll required" });

    const user = await User.findOne({ rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    if(user.emailVerified) return res.json({ success:true, message:"Already verified ✅" });

    const otp = generateOTP();
    user.otpHash = hashOTP(otp);
    user.otpExpiry = new Date(Date.now() + 10*60*1000).toISOString();
    await user.save();

    await sendMail(
      user.email,
      "ATTENDIFY OTP Resend",
      `Hello ${user.name},

Your new OTP is: ${otp}
Expires in 10 minutes.

- ATTENDIFY`
    );

    res.json({ success:true, message:"OTP resent ✅" });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Login */
app.post("/login", async (req,res)=>{
  try{
    const { loginId, password } = req.body;
    if(!loginId || !password){
      return res.json({ success:false, message:"Fill all fields" });
    }

    const user = await User.findOne({
      $or: [
        { email: loginId.toLowerCase() },
        { rollNumber: loginId },
        { name: loginId }
      ]
    });

    if(!user) return res.json({ success:false, message:"Invalid credentials" });

    if(!user.emailVerified){
      return res.json({
        success:false,
        message:"Email not verified. Enter OTP.",
        needsVerification:true,
        rollNumber:user.rollNumber
      });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.json({ success:false, message:"Invalid credentials" });

    const token = createToken(user);
    res.json({ success:true, token, user:safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Me */
app.get("/me", auth, async (req,res)=>{
  const user = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!user) return res.json({ success:false, message:"User not found" });
  res.json({ success:true, user:safeUser(user) });
});

/* ✅ Enroll */
app.post("/enroll", auth, async (req,res)=>{
  const { className } = req.body;
  if(!className) return res.json({ success:false, message:"Class required" });

  const user = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!user) return res.json({ success:false, message:"User not found" });

  user.enrolledClass = className;
  await user.save();

  res.json({ success:true, user:safeUser(user) });
});

/* ✅ Profile update */
app.post("/profile", auth, async (req,res)=>{
  try{
    const user = await User.findOne({ rollNumber:req.user.rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    const { name, rollNumber, gender, phone, dob, address, profilePic, password } = req.body;

    if(name) user.name = name;
    if(rollNumber) user.rollNumber = rollNumber;
    user.gender = gender ?? user.gender;
    user.phone = phone ?? user.phone;
    user.dob = dob ?? user.dob;
    user.address = address ?? user.address;
    if(profilePic) user.profilePic = profilePic;

    if(password && password.trim()){
      user.passwordHash = await bcrypt.hash(password.trim(), 10);
    }

    await user.save();
    res.json({ success:true, user:safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Classes */
app.get("/classes", auth, async (req,res)=>{
  const classes = await ClassModel.find().sort({ name:1 });
  res.json({ success:true, classes });
});

/* ✅ Subjects */
app.get("/subjects", auth, async (req,res)=>{
  const subjects = await SubjectModel.find().sort({ name:1 });
  res.json({ success:true, subjects });
});

/* ✅ Student Attendance */
app.get("/attendance", auth, async (req,res)=>{
  const records = await Attendance.find({ rollNumber:req.user.rollNumber }).sort({ date:-1 });
  res.json({ success:true, records });
});

/* ✅ Student Results (all segments) */
app.get("/results", auth, async (req,res)=>{
  const records = await Marks.find({ rollNumber:req.user.rollNumber }).sort({ updatedAt:-1 });
  res.json({ success:true, records });
});

/* ✅ CGPA */
app.get("/cgpa", auth, async (req,res)=>{
  const records = await Marks.find({ rollNumber:req.user.rollNumber });

  if(records.length === 0) return res.json({ success:true, cgpa:0 });

  const sum = records.reduce((a,b)=>a+(b.gradePoint || 0),0);
  const cgpa = Number((sum / records.length).toFixed(2));
  res.json({ success:true, cgpa });
});

/* ✅ PDF Marksheet */
app.get("/marksheet/pdf", auth, async (req,res)=>{
  const user = await User.findOne({ rollNumber:req.user.rollNumber });
  const marks = await Marks.find({ rollNumber:req.user.rollNumber });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${user.rollNumber}_marksheet.pdf"`);

  const doc = new PDFDocument({ margin: 40 });
  doc.pipe(res);

  doc.fontSize(18).text("ATTENDIFY - MARKSHEET", { align:"center" });
  doc.moveDown();

  doc.fontSize(12).text(`Name: ${user.name}`);
  doc.text(`Roll Number: ${user.rollNumber}`);
  doc.text(`Class: ${user.enrolledClass || "-"}`);
  doc.text(`Email: ${user.email}`);
  doc.moveDown();

  doc.fontSize(14).text("Results", { underline:true });
  doc.moveDown(0.5);

  marks.forEach(m=>{
    doc.fontSize(12).text(
      `${m.subject} | Internal:${m.internal}/30 | Assessment:${m.assessment}/20 | Exam:${m.exam}/50 | Total:${m.total}/100`
    );
  });

  doc.moveDown();
  const sumGP = marks.reduce((a,b)=>a+(b.gradePoint||0),0);
  const cgpa = marks.length ? (sumGP / marks.length).toFixed(2) : "0.00";

  doc.fontSize(14).text(`CGPA: ${cgpa}`, { align:"right" });
  doc.end();
});

/* ===============================
   OWNER / STAFF ROUTES
================================ */

/* ✅ Owner/Staff: users list */
app.get("/owner/users", auth, async (req,res)=>{
  const me = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!me) return res.json({ success:false, message:"User not found" });

  if(me.role !== "owner" && me.role !== "staff"){
    return res.status(403).json({ success:false, message:"Not allowed" });
  }

  const users = await User.find().sort({ createdAt:-1 });
  res.json({ success:true, users: users.map(safeUser) });
});

/* ✅ Owner: add user directly */
app.post("/owner/add-user", auth, async (req,res)=>{
  try{
    const me = await User.findOne({ rollNumber:req.user.rollNumber });
    if(!me || me.role !== "owner"){
      return res.status(403).json({ success:false, message:"Only owner can add users" });
    }

    const { name, email, rollNumber, password } = req.body;
    if(!name || !email || !rollNumber || !password){
      return res.json({ success:false, message:"Fill all fields" });
    }

    const cleanEmail = email.trim().toLowerCase();
    if(!isValidEmail(cleanEmail)){
      return res.json({ success:false, message:"Invalid email format" });
    }

    const emailExists = await User.findOne({ email: cleanEmail });
    if(emailExists) return res.json({ success:false, message:"Email already exists" });

    const rollExists = await User.findOne({ rollNumber });
    if(rollExists) return res.json({ success:false, message:"Roll already exists" });

    const passwordHash = await bcrypt.hash(password, 10);

    const otp = generateOTP();
    const otpHash = hashOTP(otp);
    const otpExpiry = new Date(Date.now() + 10*60*1000).toISOString();

    await User.create({
      name,
      email: cleanEmail,
      rollNumber,
      passwordHash,
      role:"student",
      enrolledClass:null,
      emailVerified:false,
      otpHash,
      otpExpiry
    });

    await sendMail(
      cleanEmail,
      "ATTENDIFY Account Created + OTP",
      `Hello ${name},

Your ATTENDIFY account was created by Admin.

OTP: ${otp}
Expires in 10 minutes.

- ATTENDIFY`
    );

    res.json({ success:true, message:"Student added + OTP sent ✅" });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Owner: add class */
app.post("/owner/class", auth, async (req,res)=>{
  const me = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!me || me.role !== "owner") return res.status(403).json({ success:false, message:"Only owner" });

  const { name } = req.body;
  if(!name) return res.json({ success:false, message:"Class name required" });

  const exists = await ClassModel.findOne({ name });
  if(exists) return res.json({ success:false, message:"Class exists" });

  await ClassModel.create({ name });
  res.json({ success:true, message:"Class added ✅" });
});

/* ✅ Owner: add subject */
app.post("/owner/subject", auth, async (req,res)=>{
  const me = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!me || me.role !== "owner") return res.status(403).json({ success:false, message:"Only owner" });

  const { name } = req.body;
  if(!name) return res.json({ success:false, message:"Subject name required" });

  const exists = await SubjectModel.findOne({ name });
  if(exists) return res.json({ success:false, message:"Subject exists" });

  await SubjectModel.create({ name });
  res.json({ success:true, message:"Subject added ✅" });
});

/* ✅ Owner: assign role + monitor classes */
app.post("/owner/user/:rollNumber/role", auth, async (req,res)=>{
  try{
    const me = await User.findOne({ rollNumber:req.user.rollNumber });
    if(!me || me.role !== "owner") return res.status(403).json({ success:false, message:"Only owner" });

    const { role, monitorClasses } = req.body;

    const user = await User.findOne({ rollNumber:req.params.rollNumber });
    if(!user) return res.json({ success:false, message:"User not found" });

    user.role = role;

    if(role === "staff"){
      user.monitorClasses = Array.isArray(monitorClasses) ? monitorClasses : [];
    }else{
      user.monitorClasses = [];
    }

    await user.save();
    res.json({ success:true, user:safeUser(user) });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Owner/Staff: attendance by date */
app.post("/owner/attendance/by-date", auth, async (req,res)=>{
  const { className, date } = req.body;

  const me = await User.findOne({ rollNumber:req.user.rollNumber });
  if(!me) return res.json({ success:false, message:"User not found" });

  if(me.role !== "owner" && me.role !== "staff"){
    return res.status(403).json({ success:false, message:"Not allowed" });
  }

  // staff permission check
  if(me.role === "staff" && !me.monitorClasses.includes(className)){
    return res.status(403).json({ success:false, message:"Staff not allowed for this class" });
  }

  const records = await Attendance.find({ className, date });
  res.json({ success:true, records });
});

/* ✅ Owner/Staff: save attendance */
app.post("/owner/attendance", auth, async (req,res)=>{
  try{
    const { rollNumber, className, status, date } = req.body;

    const me = await User.findOne({ rollNumber:req.user.rollNumber });
    if(!me) return res.json({ success:false, message:"User not found" });

    if(me.role !== "owner" && me.role !== "staff"){
      return res.status(403).json({ success:false, message:"Not allowed" });
    }

    if(me.role === "staff" && !me.monitorClasses.includes(className)){
      return res.status(403).json({ success:false, message:"Staff not allowed for this class" });
    }

    await Attendance.findOneAndUpdate(
      { rollNumber, className, date },
      { rollNumber, className, date, status },
      { upsert:true, new:true }
    );

    res.json({ success:true, message:"Attendance saved ✅" });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Owner/Staff: save marks + notify */
app.post("/owner/marks", auth, async (req,res)=>{
  try{
    const { rollNumber, className, subject, internal, assessment, exam } = req.body;

    const me = await User.findOne({ rollNumber:req.user.rollNumber });
    if(!me) return res.json({ success:false, message:"User not found" });

    if(me.role !== "owner" && me.role !== "staff"){
      return res.status(403).json({ success:false, message:"Not allowed" });
    }

    if(me.role === "staff" && !me.monitorClasses.includes(className)){
      return res.status(403).json({ success:false, message:"Staff not allowed for this class" });
    }

    const total = Number(internal || 0) + Number(assessment || 0) + Number(exam || 0);
    const gradePoint = calcGradePoint(total);

    const updated = await Marks.findOneAndUpdate(
      { rollNumber, subject, className },
      { rollNumber, className, subject, internal, assessment, exam, total, gradePoint },
      { upsert:true, new:true }
    );

    const student = await User.findOne({ rollNumber });

    if(student && student.emailVerified){
      await sendMail(
        student.email,
        `ATTENDIFY Results Updated - ${subject}`,
        `Hello ${student.name},

Your results were updated ✅

Subject: ${subject}
Internal: ${internal}/30
Assessment: ${assessment}/20
Exam: ${exam}/50
Total: ${total}/100

- ATTENDIFY`
      );

      await sendWhatsApp(
        student.phone,
        `ATTENDIFY ✅ Results Updated\n${subject}\nTotal: ${total}/100`
      );
    }

    res.json({ success:true, updated });

  }catch(err){
    res.status(500).json({ success:false, message:err.message });
  }
});

/* ✅ Start */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("✅ Server running on port", PORT));
