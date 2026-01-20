require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5050;

const isProduction = process.env.NODE_ENV === "production";

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  console.error("JWT secrets missing in .env!");
  process.exit(1);
}

app.use(
  cors({
    origin: process.env.CLIENT_URL || "https://care-xyz-client.vercel.app",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"],
    maxAge: 86400, // 24 hours preflight cache
  }),
);

// app.options(
//   "*",
//   cors({
//     origin: "https://care-xyz-client.vercel.app",
//     credentials: true,
//     allowedHeaders: ["Content-Type", "Authorization"],
//     methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
//   }),
// );

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.set("trust proxy", 1);

if (!process.env.MONGOUSER || !process.env.MONGOPASS) {
  console.error("MongoDB credentials missing in .env!");
  process.exit(1);
}

const uri = `mongodb+srv://${process.env.MONGOUSER}:${process.env.MONGOPASS}@programmingheroassignme.7jfqtzz.mongodb.net/?appName=ProgrammingHeroAssignment`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const createAccessToken = (userId) =>
  jwt.sign({ id: String(userId) }, ACCESS_SECRET, { expiresIn: "1d" });

const createRefreshToken = (userId) =>
  jwt.sign({ id: String(userId) }, REFRESH_SECRET, { expiresIn: "7d" });

const verifyToken = (req, res, next) => {
  const hdr = req.headers.authorization;
  const token =
    (hdr && hdr.startsWith("Bearer ") && hdr.slice(7)) ||
    req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, ACCESS_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.error("Token verification error:", error.message);
    res.status(401).json({ message: "Session expired" });
  }
};

const cookieOptions = isProduction
  ? {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    }
  : {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };

async function run() {
  try {
    const db = client.db("careDB");
    const users = db.collection("users");
    const services = db.collection("services");
    const bookings = db.collection("bookings");

    app.get("/", (req, res) => res.send("Care.xyz Server Running"));

    app.post("/register", async (req, res) => {
      const { name, email, password, contact, nid } = req.body;

      // Input validation
      if (!email || !password || !name)
        return res.status(400).json({ message: "Name, email, and password are required" });
      
      // Email format validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email))
        return res.status(400).json({ message: "Invalid email format" });
      
      // Password strength validation
      if (password.length < 6)
        return res.status(400).json({ message: "Password must be at least 6 characters long" });

      try {
        const exists = await users.findOne({ email });
        if (exists)
          return res.status(409).json({ message: "User already exists" });

        const hashed = await bcrypt.hash(password, 10);

        const user = {
          name,
          email,
          password: hashed,
          contact,
          nid,
          role: "user",
          createdAt: new Date(),
        };
        const result = await users.insertOne(user);

        const accessToken = createAccessToken(result.insertedId);
        const refreshToken = createRefreshToken(result.insertedId);

        res.cookie("accessToken", accessToken, cookieOptions);
        res.cookie("refreshToken", refreshToken, cookieOptions);

        res.status(201).json({ message: "Registered successfully" });
      } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Registration failed" });
      }
    });

    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      if (!email || !password)
        return res.status(400).json({ message: "Missing fields" });

      try {
        const user = await users.findOne({ email });
        if (!user)
          return res.status(401).json({ message: "Invalid credentials" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid)
          return res.status(401).json({ message: "Invalid credentials" });

        const accessToken = createAccessToken(user._id);
        const refreshToken = createRefreshToken(user._id);

        res.cookie("accessToken", accessToken, cookieOptions);
        res.cookie("refreshToken", refreshToken, cookieOptions);

        res.json({
          message: "Login successful",
          accessToken,
          user: {
            _id: user._id,
            email: user.email,
            role: user.role,
          },
        });
      } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Login failed" });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("accessToken", cookieOptions);
      res.clearCookie("refreshToken", cookieOptions);
      res.json({ message: "Logged out" });
    });

    app.post("/refresh-token", async (req, res) => {
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
      }

      try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
        const user = await users.findOne({ _id: new ObjectId(decoded.id) });
        
        if (!user) {
          return res.status(401).json({ message: "User not found" });
        }

        const newAccessToken = createAccessToken(user._id);
        const newRefreshToken = createRefreshToken(user._id);

        res.cookie("accessToken", newAccessToken, cookieOptions);
        res.cookie("refreshToken", newRefreshToken, cookieOptions);

        res.json({ 
          message: "Token refreshed",
          accessToken: newAccessToken 
        });
      } catch (error) {
        console.error("Refresh token error:", error);
        res.status(401).json({ message: "Invalid refresh token" });
      }
    });

    app.get("/me", verifyToken, async (req, res) => {
      try {
        const user = await users.findOne(
          { _id: new ObjectId(req.userId) },
          { projection: { password: 0 } },
        );
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        res.json(user);
      } catch (error) {
        console.error("Get user error:", error);
        res.status(500).json({ message: "Failed to fetch user" });
      }
    });

    app.get("/services", async (req, res) => {
      try {
        const result = await services.find().toArray();
        res.json(result);
      } catch (error) {
        console.error("Get services error:", error);
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    app.get("/service/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid service ID" });
        }

        const service = await services.findOne({
          _id: new ObjectId(id),
        });
        if (!service) {
          return res.status(404).json({ message: "Service not found" });
        }
        res.json(service);
      } catch (error) {
        console.error("Get service error:", error);
        res.status(500).json({ message: "Failed to fetch service" });
      }
    });

    app.post("/booking", verifyToken, async (req, res) => {
      try {
        const {
          serviceId,
          serviceName,
          duration,
          location,
          address,
          totalCost,
        } = req.body;

        // Input validation
        if (!serviceId || !ObjectId.isValid(serviceId)) {
          return res.status(400).json({ message: "Invalid service ID" });
        }

        if (!serviceName || !duration || !location || !address) {
          return res.status(400).json({ message: "All booking fields are required" });
        }

        if (isNaN(duration) || duration <= 0) {
          return res.status(400).json({ message: "Duration must be a positive number" });
        }

        if (isNaN(totalCost) || totalCost <= 0) {
          return res.status(400).json({ message: "Total cost must be a positive number" });
        }

        // Verify service exists
        const serviceExists = await services.findOne({ _id: new ObjectId(serviceId) });
        if (!serviceExists) {
          return res.status(404).json({ message: "Service not found" });
        }

        const booking = {
          userId: new ObjectId(req.userId),
          serviceId: new ObjectId(serviceId),
          serviceName,
          duration: Number(duration),
          location: location.trim(),
          address: address.trim(),
          totalCost: Number(totalCost),
          status: "Pending",
          createdAt: new Date(),
        };

        const result = await bookings.insertOne(booking);
        res
          .status(201)
          .json({ message: "Booking placed", id: result.insertedId });
      } catch (error) {
        console.error("Booking error:", error);
        res.status(500).json({ message: "Failed to create booking" });
      }
    });

    app.get("/my-bookings", verifyToken, async (req, res) => {
      try {
        const result = await bookings
          .find({ userId: new ObjectId(req.userId) })
          .sort({ createdAt: -1 })
          .toArray();
        res.json(result);
      } catch (error) {
        console.error("Get bookings error:", error);
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    app.patch("/cancel-booking/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid booking ID" });
        }

        // First check if booking exists and belongs to user
        const booking = await bookings.findOne({
          _id: new ObjectId(id),
          userId: new ObjectId(req.userId),
        });

        if (!booking) {
          return res.status(404).json({ message: "Booking not found" });
        }

        if (booking.status === "Cancelled") {
          return res.status(400).json({ message: "Booking is already cancelled" });
        }

        if (booking.status === "Completed") {
          return res.status(400).json({ message: "Cannot cancel completed booking" });
        }

        const result = await bookings.updateOne(
          {
            _id: new ObjectId(id),
            userId: new ObjectId(req.userId),
          },
          { $set: { status: "Cancelled", cancelledAt: new Date() } },
        );

        res.json({ message: "Booking cancelled successfully" });
      } catch (error) {
        console.error("Cancel booking error:", error);
        res.status(500).json({ message: "Failed to cancel booking" });
      }
    });

    console.log("MongoDB Connected");
  } catch (error) {
    console.error("Database connection error:", error);
  }
}

run().catch(console.error);

app.listen(port, () => console.log(`Care.xyz server running on port ${port}`));
