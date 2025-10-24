require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const helmet = require("helmet");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_ORIGIN || "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
  },
});

app.use(express.json());
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const PORT = process.env.PORT || 5000;

/* -------------------- MAKE UPLOADS FOLDER -------------------- */
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* -------------------- MODELS -------------------- */
const UserSchema = new mongoose.Schema(
  {
    name: String,
    phone_number: { type: String, unique: true },
    password: String,
    profile_image: String,
    latitude: Number,
    longitude: Number,
  },
  { timestamps: true }
);
UserSchema.methods.toPublic = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};
const User = mongoose.model("User", UserSchema);

const RiderSchema = new mongoose.Schema(
  {
    name: String,
    phone_number: { type: String, unique: true },
    password: String,
    license_plate: String,
    vehicle_image: String,
    profile_image: String,
    current_latitude: Number,
    current_longitude: Number,
  },
  { timestamps: true }
);
RiderSchema.methods.toPublic = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};
const Rider = mongoose.model("Rider", RiderSchema);

const AddressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: String,
  houseNumber: String,
  subdistrict: String,
  district: String,
  province: String,
  postalCode: String,
  latitude: Number,
  longitude: Number,
});
const Address = mongoose.model("Address", AddressSchema);

const DeliverySchema = new mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    pickup_address: { type: mongoose.Schema.Types.ObjectId, ref: "Address", default: null },
    dropoff_address: { type: mongoose.Schema.Types.ObjectId, ref: "Address", required: true },
    rider: { type: mongoose.Schema.Types.ObjectId, ref: "Rider", default: null },
    // status: 1=waiting(for pickup), 2=rider accepted (going to pickup), 3=delivering (has picked up), 4=delivered
    status: { type: Number, enum: [1, 2, 3, 4], default: 1 },
    status_updated_at: Date,
    product_name: String,
    product_detail: String,
    product_price: Number,
  },
  { timestamps: true }
);
const Delivery = mongoose.model("Delivery", DeliverySchema);

const DeliveryImageSchema = new mongoose.Schema({
  delivery: { type: mongoose.Schema.Types.ObjectId, ref: "Delivery" },
  status: { type: Number, enum: [1, 3, 4] },
  image_url: String,
  timestamp: { type: Date, default: Date.now },
});
const DeliveryImage = mongoose.model("DeliveryImage", DeliveryImageSchema);

/* -------------------- UTILITIES -------------------- */
function haversineDistance(lat1, lon1, lat2, lon2) {
  const toRad = (x) => (x * Math.PI) / 180;
  const R = 6371000;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}
const MAX_DISTANCE_M = parseInt(process.env.MAX_DISTANCE_M || "20");

/* -------------------- AUTH MIDDLEWARE -------------------- */
// auth(requiredRole) -> requiredRole optional: "user" or "rider"
function auth(requiredRole) {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization || "";
      const token = authHeader.startsWith("Bearer ")
        ? authHeader.split(" ")[1]
        : authHeader || req.query?.token;

      if (!token) return res.status(401).json({ error: "No token provided" });

      let payload;
      try {
        payload = jwt.verify(token, JWT_SECRET);
      } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
      }

      // payload should contain { id, role }
      if (!payload?.id || !payload?.role) {
        return res.status(401).json({ error: "Invalid token payload" });
      }

      // optionally enforce role
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: "Forbidden: wrong role" });
      }

      // ensure the referenced user still exists in DB
      if (payload.role === "user") {
        const u = await User.findById(payload.id).select("_id");
        if (!u) return res.status(401).json({ error: "User not found (token stale)" });
      } else if (payload.role === "rider") {
        const r = await Rider.findById(payload.id).select("_id");
        if (!r) return res.status(401).json({ error: "Rider not found (token stale)" });
      } else {
        return res.status(401).json({ error: "Unknown role in token" });
      }

      req.user = payload;
      next();
    } catch (err) {
      console.error("auth middleware error:", err);
      res.status(500).json({ error: "Internal auth error" });
    }
  };
}

/* -------------------- MULTER -------------------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) =>
    cb(
      null,
      `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(
        file.originalname
      )}`
    ),
});
const upload = multer({ storage });

/* helper: remove uploaded file by full URL or path */
function removeUploadedFile(oldUrl) {
  try {
    if (!oldUrl) return;
    // if it's a full URL like http://host/uploads/filename
    const parsed = oldUrl.split("/uploads/");
    const fname = parsed.length > 1 ? parsed[1] : path.basename(oldUrl);
    const p = path.join(UPLOAD_DIR, fname);
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
    }
  } catch (err) {
    console.warn("removeUploadedFile error:", err.message);
  }
}

/* -------------------- SOCKET.IO -------------------- */
io.use((socket, next) => {
  const token =
    socket.handshake.auth?.token || socket.handshake.query?.token || "";
  if (!token) return next();
  try {
    const raw = token.startsWith("Bearer ") ? token.split(" ")[1] : token;
    socket.user = jwt.verify(raw, JWT_SECRET);
    next();
  } catch (err) {
    console.warn("Socket auth invalid token:", err.message);
    next();
  }
});
io.on("connection", (socket) => {
  console.log("socket connected:", socket.id);
  if (socket.user?.id && socket.user?.role) {
    const role = socket.user.role,
      id = socket.user.id.toString();
    socket.join(`${role}:${id}`);
    socket.join(`${role}s`);
  }
  socket.on("join_room", (room) => socket.join(room));
  socket.on("leave_room", (room) => socket.leave(room));
  socket.on("disconnect", () => console.log("socket disconnected:", socket.id));

  // --- Rider update location ---
  socket.on("update_location", async (data) => {
    try {
      if (!socket.user || socket.user.role !== "rider") return;

      const latitude = Number(data.latitude);
      const longitude = Number(data.longitude);
      if (Number.isNaN(latitude) || Number.isNaN(longitude)) return;

      await Rider.findByIdAndUpdate(socket.user.id, {
        current_latitude: latitude,
        current_longitude: longitude,
      });

      // broadcast ให้ทุกคนเห็นว่า rider เคลื่อนที่
      io.emit("rider_location_update", {
        riderId: socket.user.id,
        latitude,
        longitude,
      });
    } catch (err) {
      console.error("update_location error:", err.message);
    }
  });
});

/* -------------------- ROUTES -------------------- */

// Health
app.get("/api/ping", (req, res) => res.json({ ok: true }));

const uploadMultiple = upload.fields([
  { name: "profile_image", maxCount: 1 },
  { name: "vehicle_image", maxCount: 1 },
]);

/* -------------------- AUTH: register / login -------------------- */
app.post("/api/auth/register", uploadMultiple, async (req, res) => {
  try {
    const { role, name, phone_number, password } = req.body;

    // basic validation
    if (!role || !["user", "rider"].includes(role))
      return res.status(400).json({ error: "role must be 'user' or 'rider'" });
    if (!name || !phone_number || !password)
      return res.status(400).json({ error: "name, phone_number and password required" });

    // normalize phone (digits only)
    const normalizedPhone = String(phone_number).replace(/\D/g, "");
    if (!/^\d{6,15}$/.test(normalizedPhone))
      return res.status(400).json({ error: "Invalid phone_number format" });

    // check uniqueness across User and Rider
    const existsUser = await User.findOne({ phone_number: normalizedPhone });
    const existsRider = await Rider.findOne({ phone_number: normalizedPhone });
    if (existsUser || existsRider)
      return res.status(409).json({ error: "Phone number already registered" });

    const hashed = await bcrypt.hash(password, 10);

    const profile_image_url = req.files?.["profile_image"]?.[0]
      ? `${req.protocol}://${req.get("host")}/uploads/${req.files["profile_image"][0].filename}`
      : null;

    const vehicle_image_url = req.files?.["vehicle_image"]?.[0]
      ? `${req.protocol}://${req.get("host")}/uploads/${req.files["vehicle_image"][0].filename}`
      : null;

    if (role === "rider") {
      const rider = new Rider({
        name,
        phone_number: normalizedPhone,
        password: hashed,
        profile_image: profile_image_url,
        vehicle_image: vehicle_image_url,
      });
      await rider.save();
      const token = jwt.sign({ id: rider._id, role: "rider" }, JWT_SECRET, {
        expiresIn: "7d",
      });
      return res.status(201).json({ rider: rider.toPublic(), token });
    }

    // user
    const user = new User({
      name,
      phone_number: normalizedPhone,
      password: hashed,
      profile_image: profile_image_url,
    });
    await user.save();
    const token = jwt.sign({ id: user._id, role: "user" }, JWT_SECRET, {
      expiresIn: "7d",
    });
    return res.status(201).json({ user: user.toPublic(), token });
  } catch (err) {
    console.error("register error:", err);
    if (err.code === 11000) return res.status(409).json({ error: "Duplicate entry" });
    res.status(500).json({ error: err.message });
  }
});

// Auth: login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { phone_number, password } = req.body;
    if (!phone_number || !password)
      return res.status(400).json({ error: "phone & password required" });

    const normalizedPhone = String(phone_number).replace(/\D/g, "");
    let user = await User.findOne({ phone_number: normalizedPhone });
    let type = "user";
    if (!user) {
      user = await Rider.findOne({ phone_number: normalizedPhone });
      type = "rider";
    }
    if (!user) return res.status(404).json({ error: "User not found" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, role: type }, JWT_SECRET, {
      expiresIn: "7d",
    });
    const payload = {};
    payload[type] = user.toPublic();
    payload.token = token;
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* -------------------- Users CRUD -------------------- */
app.get("/api/users", async (req, res) => {
  const users = await User.find();
  res.json(users.map((u) => u.toPublic()));
});
app.get("/api/users/:id", async (req, res) => {
  const { id } = req.params;
  if (!id || !mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid or missing id" });
  }
  const user = await User.findById(id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user.toPublic());
});

// update user (only the user himself or an admin in future)
app.put(
  "/api/users/:id",
  auth(),
  upload.single("profile_image"),
  async (req, res) => {
    try {
      // enforce ownership: only the same user (token) can update this profile
      if (req.user.role !== "user" || req.user.id !== req.params.id) {
        return res.status(403).json({ error: "Forbidden: cannot edit this user" });
      }

      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });

      const body = { ...req.body };

      // handle profile image: remove old file if uploading new
      if (req.file) {
        if (user.profile_image) removeUploadedFile(user.profile_image);
        body.profile_image = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
      }

      if (body.password) body.password = await bcrypt.hash(body.password, 10);

      // prevent changing phone to another registered phone
      if (body.phone_number) {
        const norm = String(body.phone_number).replace(/\D/g, "");
        if (norm !== user.phone_number) {
          const conflictUser = await User.findOne({ phone_number: norm });
          const conflictRider = await Rider.findOne({ phone_number: norm });
          if (conflictUser || conflictRider) {
            return res.status(409).json({ error: "phone_number already used" });
          }
          body.phone_number = norm;
        }
      }

      const updated = await User.findByIdAndUpdate(req.params.id, body, {
        new: true,
        runValidators: true,
      });
      res.json(updated.toPublic());
    } catch (err) {
      console.error("update user error:", err);
      res.status(400).json({ error: err.message });
    }
  }
);

app.delete("/api/users/:id", auth(), async (req, res) => {
  try {
    // only owner can delete themselves (or admin later)
    if (req.user.role !== "user" || req.user.id !== req.params.id) {
      return res.status(403).json({ error: "Forbidden: cannot delete this user" });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    // cleanup: addresses, deliveries (simple approach)
    await Address.deleteMany({ userId: req.params.id });
    await Delivery.deleteMany({ $or: [{ sender: req.params.id }, { receiver: req.params.id }] });

    // remove profile image file
    if (user.profile_image) removeUploadedFile(user.profile_image);

    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/users/phone/:phone
app.get("/api/users/phone/:phone", auth(), async (req, res) => {
  try {
    const phone = req.params.phone.replace(/\D/g, ""); // ตัวเลขเท่านั้น
    const user = await User.findOne({ phone_number: { $regex: phone + "$" } });
    if (!user) return res.status(404).json({ error: "User not found" });

    // query addresses ของ user
    const addresses = await Address.find({ userId: user._id }).select(
      "houseNumber subdistrict district province postalCode latitude longitude"
    );

    res.json({ ...user.toPublic(), addresses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* -------------------- RIDER update endpoint -------------------- */
// update rider profile (only rider himself)
app.put(
  "/api/riders/:id",
  auth(),
  upload.fields([{ name: "profile_image", maxCount: 1 }, { name: "vehicle_image", maxCount: 1 }]),
  async (req, res) => {
    try {
      if (req.user.role !== "rider" || req.user.id !== req.params.id) {
        return res.status(403).json({ error: "Forbidden: cannot edit this rider" });
      }
      const rider = await Rider.findById(req.params.id);
      if (!rider) return res.status(404).json({ error: "Rider not found" });

      const body = { ...req.body };

      if (req.files?.profile_image?.[0]) {
        if (rider.profile_image) removeUploadedFile(rider.profile_image);
        body.profile_image = `${req.protocol}://${req.get("host")}/uploads/${req.files.profile_image[0].filename}`;
      }
      if (req.files?.vehicle_image?.[0]) {
        if (rider.vehicle_image) removeUploadedFile(rider.vehicle_image);
        body.vehicle_image = `${req.protocol}://${req.get("host")}/uploads/${req.files.vehicle_image[0].filename}`;
      }

      if (body.password) body.password = await bcrypt.hash(body.password, 10);

      // prevent phone collision
      if (body.phone_number) {
        const norm = String(body.phone_number).replace(/\D/g, "");
        if (norm !== rider.phone_number) {
          const conflictUser = await User.findOne({ phone_number: norm });
          const conflictRider = await Rider.findOne({ phone_number: norm });
          if (conflictUser || conflictRider) {
            return res.status(409).json({ error: "phone_number already used" });
          }
          body.phone_number = norm;
        }
      }

      const updated = await Rider.findByIdAndUpdate(req.params.id, body, { new: true, runValidators: true });
      res.json(updated.toPublic());
    } catch (err) {
      console.error("update rider error:", err);
      res.status(400).json({ error: err.message });
    }
  }
);
// GET rider profile by id
app.get("/api/riders/:id", auth(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid rider ID" });
    }

    const rider = await Rider.findById(id);
    if (!rider) return res.status(404).json({ error: "Rider not found" });

    res.json(rider.toPublic());
  } catch (err) {
    console.error("get rider profile error:", err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------- Addresses -------------------- */
app.post("/api/addresses", auth(), async (req, res) => {
  try {
    const { userId } = req.body;
    if (!mongoose.Types.ObjectId.isValid(userId))
      return res.status(400).json({ error: "Invalid userId" });

    const addr = new Address(req.body);
    await addr.save();
    res.status(201).json(addr);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/addresses/:userId", auth(), async (req, res) => {
  try {
    const addrs = await Address.find({ userId: req.params.userId });
    res.json(addrs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/addresses/:id", auth(), async (req, res) => {
  try {
    const addr = await Address.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!addr) return res.status(404).json({ error: "Address not found" });
    res.json(addr);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/addresses/:id", auth(), async (req, res) => {
  try {
    const addr = await Address.findByIdAndDelete(req.params.id);
    if (!addr) return res.status(404).json({ error: "Address not found" });
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* -------------------- Deliveries -------------------- */
// POST /api/deliveries
app.post("/api/deliveries", auth(), async (req, res) => {
  try {
    let { sender, receiver, dropoff_address, pickup_address, product_name, product_detail, product_price } = req.body;

    // --- Lookup sender ---
    let senderUser;
    if (!sender) {
      // ใช้ user ที่ login มา
      if (req.user.role !== "user") return res.status(403).json({ error: "Only user can create delivery" });
      senderUser = await User.findById(req.user.id);
      if (!senderUser) return res.status(404).json({ error: "Sender not found" });
      sender = senderUser._id;
    } else if (/^\d+$/.test(String(sender))) {
      // ถ้า sender เป็นเบอร์โทร
      senderUser = await User.findOne({ phone_number: String(sender).replace(/\D/g, "") });
      if (!senderUser) return res.status(404).json({ error: "Sender not found by phone" });
      sender = senderUser._id;
    }

    // --- Lookup receiver ---
    let receiverUser;
    if (!receiver) return res.status(400).json({ error: "Receiver required" });
    else if (/^\d+$/.test(String(receiver))) {
      receiverUser = await User.findOne({ phone_number: String(receiver).replace(/\D/g, "") });
      if (!receiverUser) return res.status(404).json({ error: "Receiver not found by phone" });
      receiver = receiverUser._id;
    }

    // --- Validate dropoff_address ---
    if (!dropoff_address) return res.status(400).json({ error: "Dropoff address required" });

    // --- สร้าง Delivery ---
    const delivery = new Delivery({
      sender,
      receiver,
      dropoff_address,
      pickup_address: pickup_address || null,
      product_name,
      product_detail,
      product_price: product_price || 0,
      status: 1,
    });

    await delivery.save();

    // Populate สำหรับ response
    const populatedDelivery = await Delivery.findById(delivery._id)
      .populate("sender receiver rider pickup_address dropoff_address");

    res.status(201).json(populatedDelivery);
  } catch (err) {
    console.error("create delivery error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/deliveries/user/:userId", auth(), async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid userId" });
    }
    const deliveries = await Delivery.find({
      $or: [{ sender: userId }, { receiver: userId }],
    }).populate("sender receiver rider pickup_address dropoff_address");

    res.json(deliveries);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/deliveries", auth(), async (req, res) => {
  const deliveries = await Delivery.find().populate(
    "sender receiver rider pickup_address dropoff_address"
  );
  res.json(deliveries);
});

app.get("/api/deliveries/:id", auth(), async (req, res) => {
  const delivery = await Delivery.findById(req.params.id).populate(
    "sender receiver rider pickup_address dropoff_address"
  );
  if (!delivery) return res.status(404).json({ error: "Delivery not found" });
  res.json(delivery);
});

/* -------------------- Assign delivery to rider -------------------- */
// PATCH /api/deliveries/:id/assign
// Rider can only accept if:
//  - delivery.rider is null (atomic update)
//  - rider currently has no other active jobs (status 2 or 3)
//  - rider's current location is within MAX_DISTANCE_M of pickup_address coordinates (if pickup_address exists)
app.patch("/api/deliveries/:id/assign", auth("rider"), async (req, res) => {
  try {
    const riderId = req.user.id;
    const deliveryId = req.params.id;

    // ensure rider doesn't have another active job
    const active = await Delivery.findOne({
      rider: riderId,
      status: { $in: [2, 3] },
    });
    if (active) return res.status(400).json({ error: "You already have an active job" });

    // fetch delivery + pickup address data
    const delivery = await Delivery.findById(deliveryId).populate("pickup_address");
    if (!delivery) return res.status(404).json({ error: "Delivery not found" });
    if (delivery.rider) return res.status(400).json({ error: "Delivery already assigned" });

    // check rider current location exists
    const rider = await Rider.findById(riderId);
    if (!rider) return res.status(404).json({ error: "Rider not found" });

    // if pickup_address has coordinates, check distance
    if (delivery.pickup_address && delivery.pickup_address.latitude != null && delivery.pickup_address.longitude != null) {
      if (rider.current_latitude == null || rider.current_longitude == null) {
        return res.status(400).json({ error: "Rider location unknown. Cannot accept job." });
      }
      const dist = haversineDistance(
        Number(rider.current_latitude),
        Number(rider.current_longitude),
        Number(delivery.pickup_address.latitude),
        Number(delivery.pickup_address.longitude)
      );
      if (dist > MAX_DISTANCE_M) {
        return res.status(400).json({ error: `Too far from pickup location (${Math.round(dist)}m). Must be within ${MAX_DISTANCE_M}m to accept.` });
      }
    }

    // atomic assign: ensure rider:null
    const assigned = await Delivery.findOneAndUpdate(
      { _id: deliveryId, rider: null },
      { $set: { rider: riderId, status: 2, status_updated_at: new Date() } },
      { new: true }
    ).populate("sender receiver rider pickup_address dropoff_address");

    if (!assigned) return res.status(400).json({ error: "Failed to assign (maybe assigned by someone else)" });

    // broadcast update real-time
    io.emit("delivery_assigned", assigned);

    res.json(assigned);
  } catch (err) {
    console.error("assign error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/deliveries/waiting", auth("rider"), async (req, res) => {
  const deliveries = await Delivery.find({ rider: null }).populate(
    "sender receiver pickup_address dropoff_address"
  );
  res.json(deliveries);
});

/* -------------------- Delivery Images -------------------- */
app.post(
  "/api/delivery-images",
  auth(),
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: "Image required" });
      const { delivery, status } = req.body;
      if (!mongoose.Types.ObjectId.isValid(delivery))
        return res.status(400).json({ error: "Invalid delivery ID" });
      const url = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
      const img = new DeliveryImage({ delivery, status, image_url: url });
      await img.save();
      res.status(201).json(img);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

/* -------------------- STATUS UPDATE ENDPOINT -------------------- */
// PUT /api/deliveries/:id/status
app.put("/api/deliveries/:id/status", auth(), async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = [1, 2, 3, 4]; // 1=waiting,2=accepted/going to pickup,3=delivering,4=delivered
    if (!validStatuses.includes(Number(status))) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const delivery = await Delivery.findById(req.params.id);
    if (!delivery) return res.status(404).json({ error: "Delivery not found" });

    // --- ตรวจ role ---
    if (req.user.role === "user") {
      // sender หรือ receiver เท่านั้นที่อัปเดตได้ (บาง action เช่น cancel)
      if (
        !delivery.sender.equals(req.user.id) &&
        !delivery.receiver.equals(req.user.id)
      ) {
        return res.status(403).json({ error: "Forbidden for this user" });
      }
    }

    if (req.user.role === "rider") {
      // ไรเดอร์อัปเดตสถานะระหว่างทาง
      if (delivery.rider && !delivery.rider.equals(req.user.id)) {
        return res.status(403).json({ error: "Not assigned rider" });
      }

      // If rider tries to set delivered (4) or picked up (3), optionally enforce proximity check to pickup/dropoff
      if (Number(status) === 3 || Number(status) === 4) {
        // pickup for status 3 should verify rider is near pickup address
        // status 4 (delivered) should verify rider is near dropoff address
        const targetAddrId = Number(status) === 3 ? delivery.pickup_address : delivery.dropoff_address;
        if (targetAddrId) {
          const addr = await Address.findById(targetAddrId);
          if (addr && (addr.latitude != null && addr.longitude != null)) {
            const r = await Rider.findById(req.user.id);
            if (!r || r.current_latitude == null || r.current_longitude == null) {
              return res.status(400).json({ error: "Rider location unknown. Cannot update status to this value." });
            }
            const dist = haversineDistance(
              Number(r.current_latitude),
              Number(r.current_longitude),
              Number(addr.latitude),
              Number(addr.longitude)
            );
            if (dist > MAX_DISTANCE_M) {
              return res.status(400).json({ error: `Too far from required location (${Math.round(dist)}m). Must be within ${MAX_DISTANCE_M}m to set this status.` });
            }
          }
        }
      }
    }

    // --- บันทึกสถานะใหม่ ---
    delivery.status = Number(status);
    delivery.status_updated_at = new Date();
    await delivery.save();

    // --- populate เพื่อส่งข้อมูลเต็มกลับ ---
    const populated = await Delivery.findById(delivery._id).populate(
      "sender receiver rider pickup_address dropoff_address"
    );

    // --- emit real-time event ---
    io.emit("delivery_status_updated", populated);

    res.json(populated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* -------------------- DATABASE & START -------------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err))

  .then(() =>
    server.listen(PORT, () => console.log(`Server running on port ${PORT}`))
  )
  .catch((err) => console.error("MongoDB connection error:", err));

module.exports = app;
