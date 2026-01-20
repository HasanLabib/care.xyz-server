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

// Rate limiting middleware (simple implementation)
const rateLimitMap = new Map();

const rateLimit = (windowMs, maxRequests) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    if (rateLimitMap.has(clientIP)) {
      const requests = rateLimitMap.get(clientIP).filter(time => time > windowStart);
      rateLimitMap.set(clientIP, requests);
    }
    
    const requests = rateLimitMap.get(clientIP) || [];
    
    if (requests.length >= maxRequests) {
      return res.status(429).json({ 
        message: "Too many requests, please try again later" 
      });
    }
    
    requests.push(now);
    rateLimitMap.set(clientIP, requests);
    next();
  };
};

// Rate limiters
const authLimiter = rateLimit(15 * 60 * 1000, 5); // 5 requests per 15 minutes
const generalLimiter = rateLimit(15 * 60 * 1000, 100); // 100 requests per 15 minutes

app.use(
  cors({
    origin: process.env.CLIENT_URL || "https://care-xyz-client.vercel.app",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS", "PUT"],
    maxAge: 86400,
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.set("trust proxy", 1);

// Apply general rate limiting to all routes
app.use(generalLimiter);

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
      maxAge: 7 * 24 * 60 * 60 * 1000,
    }
  : {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    };

async function run() {
  try {
    const db = client.db("careDB");
    const users = db.collection("users");
    const services = db.collection("services");
    const bookings = db.collection("bookings");

    // Create database indexes for performance
    try {
      await users.createIndex({ email: 1 }, { unique: true });
      await bookings.createIndex({ userId: 1 });
      await bookings.createIndex({ serviceId: 1 });
      await bookings.createIndex({ createdAt: -1 });
      console.log("Database indexes created successfully");
    } catch (indexError) {
      console.log("Database indexes already exist or creation failed:", indexError.message);
    }

    app.get("/", (req, res) => res.send("Care.xyz Server Running"));

    // Health check endpoint for monitoring
    app.get("/health", async (req, res) => {
      try {
        // Check database connection
        await client.db("admin").command({ ping: 1 });
        res.json({ 
          status: "healthy", 
          timestamp: new Date().toISOString(),
          database: "connected",
          service: "Care.xyz API"
        });
      } catch (error) {
        res.status(503).json({ 
          status: "unhealthy", 
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    });

    app.post("/register", authLimiter, async (req, res) => {
      const { name, email, password, contact, nid } = req.body;

      // Input validation and sanitization
      if (!email || !password || !name)
        return res
          .status(400)
          .json({ message: "Name, email, and password are required" });

      // Sanitize and validate inputs
      const sanitizedName = name.trim();
      const sanitizedEmail = email.trim().toLowerCase();
      const sanitizedContact = contact ? contact.trim() : '';
      const sanitizedNid = nid ? nid.trim() : '';

      if (!sanitizedName || sanitizedName.length < 2)
        return res.status(400).json({ message: "Name must be at least 2 characters" });

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(sanitizedEmail))
        return res.status(400).json({ message: "Invalid email format" });

      if (password.length < 8)
        return res
          .status(400)
          .json({ message: "Password must be at least 8 characters long" });

      // Check password complexity
      if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password))
        return res
          .status(400)
          .json({ message: "Password must contain uppercase, lowercase, and number" });

      try {
        const exists = await users.findOne({ email: sanitizedEmail });
        if (exists)
          return res.status(409).json({ message: "User already exists" });

        const hashed = await bcrypt.hash(password, 10);

        const user = {
          name: sanitizedName,
          email: sanitizedEmail,
          password: hashed,
          contact: sanitizedContact,
          nid: sanitizedNid,
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

    app.post("/login", authLimiter, async (req, res) => {
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
          accessToken: newAccessToken,
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
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const result = await services.find()
          .skip(skip)
          .limit(limit)
          .toArray();
        
        const total = await services.countDocuments();
        
        // For backward compatibility, return just the array if no pagination requested
        if (!req.query.page && !req.query.limit) {
          res.json(result);
        } else {
          res.json({
            services: result,
            pagination: {
              page,
              limit,
              total,
              pages: Math.ceil(total / limit)
            }
          });
        }
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

        if (!serviceId || !ObjectId.isValid(serviceId)) {
          return res.status(400).json({ message: "Invalid service ID" });
        }

        // Sanitize and validate inputs
        const sanitizedServiceName = serviceName ? serviceName.trim() : '';
        const sanitizedLocation = location ? location.trim() : '';
        const sanitizedAddress = address ? address.trim() : '';

        if (!sanitizedServiceName || !duration || !sanitizedLocation || !sanitizedAddress) {
          return res
            .status(400)
            .json({ message: "All booking fields are required" });
        }

        if (isNaN(duration) || duration <= 0 || duration > 365) {
          return res
            .status(400)
            .json({ message: "Duration must be between 1 and 365 days" });
        }

        if (isNaN(totalCost) || totalCost <= 0) {
          return res
            .status(400)
            .json({ message: "Total cost must be a positive number" });
        }

        // Re-fetch service to validate current price and availability
        const serviceExists = await services.findOne({
          _id: new ObjectId(serviceId),
        });
        if (!serviceExists) {
          return res.status(404).json({ message: "Service not found" });
        }

        // Validate cost calculation server-side
        const expectedCost = serviceExists.price * Number(duration);
        if (Math.abs(expectedCost - Number(totalCost)) > 0.01) {
          return res.status(400).json({ 
            message: "Cost calculation mismatch. Please refresh and try again." 
          });
        }

        const booking = {
          userId: new ObjectId(req.userId),
          serviceId: new ObjectId(serviceId),
          serviceName: sanitizedServiceName,
          duration: Number(duration),
          location: sanitizedLocation,
          address: sanitizedAddress,
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

        const booking = await bookings.findOne({
          _id: new ObjectId(id),
          userId: new ObjectId(req.userId),
        });

        if (!booking) {
          return res.status(404).json({ message: "Booking not found" });
        }

        if (booking.status === "Cancelled") {
          return res
            .status(400)
            .json({ message: "Booking is already cancelled" });
        }

        if (booking.status === "Completed") {
          return res
            .status(400)
            .json({ message: "Cannot cancel completed booking" });
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
