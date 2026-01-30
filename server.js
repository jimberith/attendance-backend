import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";

dotenv.config();
const app = express();
const upload = multer();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

/* =======================
   DATABASE
======================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

/* =======================
   MODELS
======================= */
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  rollNumber: String,
  passwordHash: String,

  role: { type: String, default: "student" },
  enrolledClass: String,

  gender: String,
  phone: String,
  dob: String,
  address: String,

  profilePic: String,
  faceImage: String,

  locks: {
    profileUpdateLocked: { type: Boolean, default: false },
    photoUploadLocked: { type: Boolean, default: false },
    faceRegisterLocked: { type: Boolean, default: false }
  }
});

const AttendanceSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  status: String
});

const RequestSchema = new mongoose.Schema({
  rollNumber: String,
  className: String,
  date: String,
  latitude: Number,
  longitude: Number,
  distance: Number,
  status: { type: String, default: "pending" }
});

const User = mongoose.model("User", UserSchema);
const Attendance = mongoose.model("Attendance", AttendanceSchema);
const Request = mongoose.model("Request", RequestSchema);

/* =======================
   AUTH HELPERS
======================= */
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ success: false });

  try {
    req.user = jwt.verify(h.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false });
  }
}

function makeToken(user) {
  return jwt.sign(
    { rollNumber: user.rollNumber, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

/* =======================
   GEO DISTANCE
======================= */
function distance(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = d => d * Math.PI / 180;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  return R * 2 * Math.asin(
    Math.sqrt(
      Math.sin(dLat / 2) ** 2 +
      Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) ** 2
    )
  );
}

const CLASS_LOCATION = {
  lat: 11.2742,
  lon: 77.6049,
  radius: 50
};

/* =======================
   AUTH ROUTES
======================= */
app.post("/signup", async (req, res) => {
  const { name, email, rollNumber, password } = req.body;
  if (!name || !email || !rollNumber || !password)
    return res.json({ success: false, message: "Missing fields" });

  if (await User.findOne({ $or: [{ email }, { rollNumber }] }))
    return res.json({ success: false, message: "User exists" });

  const role = (await User.countDocuments()) === 0 ? "owner" : "student";

  const user = await User.create({
    name,
    email,
    rollNumber,
    passwordHash: await bcrypt.hash(password, 10),
    role
  });

  res.json({ success: true, token: makeToken(user) });
});

app.post("/login", async (req, res) => {
  const { loginId, password } = req.body;

  const user = await User.findOne({
    $or: [{ email: loginId }, { rollNumber: loginId }, { name: loginId }]
  });

  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.json({ success: false, message: "Invalid credentials" });

  res.json({ success: true, token: makeToken(user) });
});

app.get("/me", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  res.json({ success: true, user });
});

/* =======================
   PROFILE
======================= */
app.post("/profile", auth, async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });

  if (user.locks?.profileUpdateLocked)
    return res.json({ success: false, message: "Profile locked" });

  const {
    name, rollNumber, gender,
    phone, dob, address, password, profilePic
  } = req.body;

  if (name !== undefined) user.name = name;
  if (rollNumber !== undefined) user.rollNumber = rollNumber;
  if (gender !== undefined) user.gender = gender;
  if (phone !== undefined) user.phone = phone;
  if (dob !== undefined) user.dob = dob;
  if (address !== undefined) user.address = address;
  if (profilePic !== undefined) user.profilePic = profilePic;

  if (password)
    user.passwordHash = await bcrypt.hash(password, 10);

  await user.save();
  res.json({ success: true, user });
});

/* =======================
   FACE REGISTER
======================= */
app.post("/face/enroll", auth, upload.single("image"), async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });

  if (user.locks?.faceRegisterLocked)
    return res.json({ success: false, message: "Face register locked" });

  user.faceImage = req.file.buffer.toString("base64");
  await user.save();

  res.json({ success: true, user });
});

/* =======================
   ATTENDANCE (FACE + GEO)
======================= */
app.post("/attendance/face", auth, upload.single("image"), async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  const { lat, lng } = req.body;

  const d = distance(
    Number(lat),
    Number(lng),
    CLASS_LOCATION.lat,
    CLASS_LOCATION.lon
  );

  const date = new Date().toISOString().split("T")[0];

  if (d <= CLASS_LOCATION.radius) {
    await Attendance.create({
      rollNumber: user.rollNumber,
      className: user.enrolledClass,
      date,
      status: "Present"
    });
    return res.json({ success: true, message: "Attendance marked" });
  }

  res.json({ success: false, message: "Out of range" });
});

/* =======================
   ATTENDANCE REQUEST
======================= */
app.post("/attendance/request", auth, upload.single("image"), async (req, res) => {
  const user = await User.findOne({ rollNumber: req.user.rollNumber });
  const { lat, lng } = req.body;

  const d = distance(
    Number(lat),
    Number(lng),
    CLASS_LOCATION.lat,
    CLASS_LOCATION.lon
  );

  const date = new Date().toISOString().split("T")[0];

  await Request.create({
    rollNumber: user.rollNumber,
    className: user.enrolledClass,
    date,
    latitude: lat,
    longitude: lng,
    distance: d
  });

  res.json({ success: true, message: "Request sent" });
});

/* =======================
   OWNER – REQUESTS
======================= */
app.get("/owner/attendance/requests", auth, async (req, res) => {
  if (req.user.role === "student")
    return res.json({ success: false });

  const requests = await Request.find({ status: "pending" });
  res.json({ success: true, requests });
});

app.post("/owner/attendance/request/approve", auth, async (req, res) => {
  if (req.user.role === "student")
    return res.json({ success: false });

  const { requestId } = req.body;
  const r = await Request.findById(requestId);

  await Attendance.create({
    rollNumber: r.rollNumber,
    className: r.className,
    date: r.date,
    status: "Present"
  });

  r.status = "done";
  await r.save();
  res.json({ success: true });
});

app.post("/owner/attendance/request/reject", auth, async (req, res) => {
  if (req.user.role === "student")
    return res.json({ success: false });

  const { requestId } = req.body;
  const r = await Request.findById(requestId);

  await Attendance.create({
    rollNumber: r.rollNumber,
    className: r.className,
    date: r.date,
    status: "Absent"
  });

  r.status = "done";
  await r.save();
  res.json({ success: true });
});

/* =======================
   SERVER
======================= */
app.listen(10000, () =>
  console.log("ATTENDIFY backend running on port 10000")
);
