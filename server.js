// server.js
const express = require("express");
const http = require("http");
const session = require("express-session");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const MongoStore = require("connect-mongo");
app.use(
  session({
    secret: "supersecretkey123",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: "mongodb+srv://chatbot_user:Chat-7096@chatbot-admin.eozun8v.mongodb.net/chatApp",
      ttl: 7 * 24 * 60 * 60, // sessions last 7 days
    }),
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // cookie valid for 7 days
  })
);


// =============================
// MongoDB Connection
// (keep your connection string here)
mongoose
  .connect("mongodb+srv://chatbot_user:Chat-7096@chatbot-admin.eozun8v.mongodb.net/?appName=chatbot-admin")
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err));

// =============================
// Schemas
const SessionSchema = new mongoose.Schema({
  sessionId: String,
  name: { type: String, default: "Visitor" },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  unreadCount: { type: Number, default: 0 },
});

const MessageSchema = new mongoose.Schema({
  sessionId: String,
  sender: String,          // "User" or "Owner"
  message: String,
  ts: { type: Date, default: Date.now },
  status: { type: String, default: "sent" }  // NEW
});


const Session = mongoose.model("Session", SessionSchema);
const Message = mongoose.model("Message", MessageSchema);

const OWNER_ROOM = "owners";
function genId() {
  return crypto.randomBytes(4).toString("hex");
}
function formatTime(date) {
  return new Date(date).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// =============================
// AUTHENTICATION (unchanged)
const OWNER_CREDENTIALS = {
  username: "admin",
  password: "12345",
};

app.get("/login", (req, res) => {
  if (req.session.authenticated) return res.redirect("/owner.html");
  res.sendFile(path.join(__dirname, "public/login.html"));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === OWNER_CREDENTIALS.username && password === OWNER_CREDENTIALS.password) {
    req.session.authenticated = true;
    return res.redirect("/owner.html");
  }
  res.send("<script>alert('Invalid credentials!'); window.location='/login';</script>");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.use((req, res, next) => {
  if (req.path === "/owner.html" && !req.session.authenticated) return res.redirect("/login");
  next();
});

// =============================
// Helper to build owner list
async function getUserList() {
  const sessions = await Session.find({}).sort({ lastSeen: -1 });
  const lastMsgs = {};
  const msgs = await Message.aggregate([
    { $sort: { ts: -1 } },
    { $group: { _id: "$sessionId", message: { $first: "$message" }, sender: { $first: "$sender" }, ts: { $first: "$ts" } } },
  ]);
  msgs.forEach((m) => (lastMsgs[m._id] = m));
  return sessions.map((s) => ({
    sessionId: s.sessionId,
    name: s.name,
    lastSeen: s.lastSeen,
    unreadCount: s.unreadCount,
    lastMessage: lastMsgs[s.sessionId] || null,
  }));
}

async function emitUserList() {
  io.to(OWNER_ROOM).emit("userList", await getUserList());
}

// =============================
// SOCKET.IO
io.on("connection", (socket) => {
  console.log("⚡ Connected:", socket.id);

  // Visitor (or reused visitor) initializes
  socket.on("init", async (data) => {
    let sid = data?.sessionId;
    let session = null;

    if (!sid || !(session = await Session.findOne({ sessionId: sid }))) {
      sid = genId();
      session = await Session.create({ sessionId: sid, name: data?.name || "Visitor" });
      console.log("🆕 Created session:", sid);
    } else {
      session.lastSeen = Date.now();
      await session.save();
      console.log("🔄 Reconnected session:", sid);
    }

    // IMPORTANT: join visitor private room
    socket.join(sid);

    socket.emit("session", { sessionId: sid });
    emitUserList();
  });

  // Owner joins owner room
  socket.on("ownerJoin", async () => {
  socket.join(OWNER_ROOM);
  console.log("👑 Owner joined");

  // Send visitor list immediately to the new owner
  socket.emit("userList", await getUserList());

  // Keep syncing for other owners
  emitUserList();
});

  // Visitor -> Owner
  socket.on("chatMessage", async (data) => {
    const { sessionId, message } = data || {};
    if (!sessionId || !message) return;

    // Save message
    const msg = await Message.create({ sessionId, sender: "User", message, status: "sent" });
    await Session.updateOne({ sessionId }, { lastSeen: Date.now(), $inc: { unreadCount: 1 } });

    // Send to owner dashboard
    io.to(OWNER_ROOM).emit("chatMessage", {
      sessionId,
      sender: "User",
      message,
      ts: msg.ts,
      time: formatTime(msg.ts),
    });

    emitUserList();
  });

  // Owner -> Visitor
 socket.on("ownerMessage", async (data) => {   // <-- this must be async
  const { sessionId, message } = data || {};
  if (!sessionId || !message) return;

  // Create message and mark as sent
  const msg = await Message.create({ sessionId, sender: "Owner", message, status: "sent" });
  await Session.updateOne({ sessionId }, { unreadCount: 0 });

  // Emit to that specific visitor
  io.to(sessionId).emit("chatMessage", {
    sessionId,
    sender: "Owner",
    message,
    ts: msg.ts,
    time: formatTime(msg.ts),
    status: "delivered",
  });

  // Update DB to delivered
  await Message.updateOne({ _id: msg._id }, { status: "delivered" });

  // Notify other owners
  socket.to(OWNER_ROOM).emit("ownerSentUpdate", {
    sessionId,
    message,
    ts: msg.ts,
  });

  emitUserList(); // Refresh sidebar for all owners
});


  // Owner requests history for a session
  socket.on("requestHistory", async (data) => {
    const msgs = await Message.find({ sessionId: data.sessionId }).sort({ ts: 1 });
    await Session.updateOne({ sessionId: data.sessionId }, { unreadCount: 0 });
    const formatted = msgs.map((m) => ({ ...m._doc, time: formatTime(m.ts) }));
    socket.emit("history", { sessionId: data.sessionId, messages: formatted });
    emitUserList();
  });

  // Typing indicator
  socket.on("typing", (data) => {
    const { sessionId, sender } = data || {};
    if (!sessionId) return;

    if (sender === "User") {
      // visitor typing -> notify owners
      socket.broadcast.to(OWNER_ROOM).emit("typing", { sessionId, sender: "User" });
    } else if (sender === "Owner") {
      // owner typing -> notify only that visitor's room
      io.to(sessionId).emit("typing", { sessionId, sender: "Owner" });
    }
  });

  // mark seen (owner opened chat)
  socket.on("markSeen", async ({ sessionId }) => {
  if (!sessionId) return;
  await Message.updateMany(
    { sessionId, status: { $ne: "seen" } },
    { $set: { status: "seen" } }
  );
  io.to(sessionId).emit("seenUpdate", { sessionId });
  io.to(OWNER_ROOM).emit("seenUpdate", { sessionId });
});

  socket.on("disconnect", () => {
    console.log("❌ Disconnected:", socket.id);
  });
});

// serve static files
app.use(express.static("public"));

const PORT = 3000;
server.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));