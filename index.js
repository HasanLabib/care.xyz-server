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

const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET ||
  (isProduction ? "production-access-secret-fallback" : "dev-access-secret");

const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ||
  (isProduction ? "production-refresh-secret-fallback" : "dev-refresh-secret");

app.use(
  cors({
    origin: isProduction ? ["https://vercel.com"] : true,
    credentials: true,
  }),
);

app.use(express.json());
app.use(cookieParser());
app.set("trust proxy", 1);

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
    }
  : {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    };

async function run() {
  try {
    await client.connect();
    const db = client.db("careDB");
    const users = db.collection("users");
    const services = db.collection("services");
    const bookings = db.collection("bookings");

    app.get("/", (req, res) => res.send("Care.xyz Server Running"));

    app.post("/register", async (req, res) => {
      const { name, email, password, contact, nid } = req.body;

      if (!email || !password)
        return res.status(400).json({ message: "Missing fields" });
      if (!ACCESS_SECRET || !REFRESH_SECRET)
        return res.status(500).json({ message: "Server misconfigured" });

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
      if (!ACCESS_SECRET || !REFRESH_SECRET)
        return res.status(500).json({ message: "Server misconfigured" });

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

        res.json({ message: "Login successful" });
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

        if (!serviceId || !ObjectId.isValid(serviceId)) {
          return res.status(400).json({ message: "Invalid service ID" });
        }

        const booking = {
          userId: new ObjectId(req.userId),
          serviceId: new ObjectId(serviceId),
          serviceName,
          duration,
          location,
          address,
          totalCost,
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

        const result = await bookings.updateOne(
          {
            _id: new ObjectId(id),
            userId: new ObjectId(req.userId),
          },
          { $set: { status: "Cancelled" } },
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Booking not found" });
        }

        res.json({ message: "Booking cancelled" });
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
