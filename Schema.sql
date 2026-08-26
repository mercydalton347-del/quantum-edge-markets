require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});


/* =========================
   MIDDLEWARE
========================= */

app.use(
  cors({
    origin: process.env.FRONTEND_URL
      ? process.env.FRONTEND_URL.split(",")
      : true
  })
);

app.use(express.json());


/* =========================
   DATABASE
========================= */

async function query(text, params) {
  return pool.query(text, params);
}


/* =========================
   AUTHENTICATION
========================= */

function auth(req, res, next) {

  const header =
    req.headers.authorization || "";

  const token =
    header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  try {

    req.user =
      jwt.verify(token, JWT_SECRET);

    next();

  } catch {

    return res.status(401).json({
      error: "Invalid or expired token"
    });

  }
}


/* =========================
   PUBLIC USER DATA
========================= */

function publicUser(user) {

  return {

    id: user.id,

    name: user.name,

    email: user.email,

    accountId: user.account_id,

    balance: Number(user.balance),

    profit: Number(user.profit),

    bonus: Number(user.bonus),

    investment: Number(user.investment),

    duration: user.duration,

    status: user.status

  };

}


/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", async (req, res) => {

  try {

    await query("SELECT 1");

    res.json({
      ok: true,
      service: "Quantum Edge Markets API"
    });

  } catch (error) {

    res.status(503).json({
      ok: false,
      error: "Database unavailable"
    });

  }

});


/* =========================
   SIGN UP
========================= */

app.post("/api/auth/signup", async (req, res) => {

  const {
    name,
    email,
    password
  } = req.body;

  if (
    !name ||
    !email ||
    !password ||
    password.length < 8
  ) {

    return res.status(400).json({
      error:
        "Name, email and password of at least 8 characters are required"
    });

  }

  const normalizedEmail =
    String(email)
      .trim()
      .toLowerCase();

  try {

    const exists = await query(
      "SELECT id FROM users WHERE email=$1",
      [normalizedEmail]
    );

    if (exists.rowCount) {

      return res.status(409).json({
        error: "Email already registered"
      });

    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const result = await query(

      `INSERT INTO users
      (name,email,password_hash)
      VALUES($1,$2,$3)

      RETURNING
      id,
      name,
      email,
      account_id,
      balance,
      profit,
      bonus,
      investment,
      duration,
      status`,

      [
        name.trim(),
        normalizedEmail,
        passwordHash
      ]

    );

    const user =
      result.rows[0];

    const token =
      jwt.sign(
        { userId: user.id },
        JWT_SECRET,
        { expiresIn: "8h" }
      );

    res.status(201).json({

      token,

      user:
        publicUser(user)

    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Unable to create account"
    });

  }

});


/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {

  const {
    email,
    password
  } = req.body;

  try {

    const result = await query(

      "SELECT * FROM users WHERE email=$1",

      [
        String(email || "")
          .trim()
          .toLowerCase()
      ]

    );

    if (!result.rowCount) {

      return res.status(401).json({
        error: "Invalid email or password"
      });

    }

    const user =
      result.rows[0];

    if (user.status === "suspended") {

      return res.status(403).json({
        error: "Account suspended"
      });

    }

    const valid =
      await bcrypt.compare(
        password || "",
        user.password_hash
      );

    if (!valid) {

      return res.status(401).json({
        error: "Invalid email or password"
      });

    }

    const token =
      jwt.sign(
        { userId: user.id },
        JWT_SECRET,
        { expiresIn: "8h" }
      );

    res.json({

      token,

      user:
        publicUser(user)

    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Login unavailable"
    });

  }

});


/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {

  try {

    const result = await query(

      `SELECT
      id,
      name,
      email,
      account_id,
      balance,
      profit,
      bonus,
      investment,
      duration,
      status

      FROM users

      WHERE id=$1`,

      [req.user.userId]

    );

    if (!result.rowCount) {

      return res.status(404).json({
        error: "User not found"
      });

    }

    res.json({
      user:
        publicUser(result.rows[0])
    });

  } catch (error) {

    res.status(500).json({
      error: "Unable to load account"
    });

  }

});


/* =========================
   UPDATE PROFILE
========================= */

app.put("/api/me", auth, async (req, res) => {

  const name =
    String(req.body.name || "")
      .trim();

  if (!name) {

    return res.status(400).json({
      error: "Name is required"
    });

  }

  try {

    const result = await query(

      `UPDATE users

      SET
      name=$1,
      updated_at=NOW()

      WHERE id=$2

      RETURNING
      id,
      name,
      email,
      account_id,
      balance,
      profit,
      bonus,
      investment,
      duration,
      status`,

      [
        name,
        req.user.userId
      ]

    );

    if (!result.rowCount) {

      return res.status(404).json({
        error: "User not found"
      });

    }

    res.json({
      user:
        publicUser(result.rows[0])
    });

  } catch (error) {

    res.status(500).json({
      error: "Unable to update profile"
    });

  }

});


/* =========================
   WITHDRAWAL REQUEST
========================= */

app.post(
  "/api/withdrawals",
  auth,
  async (req, res) => {

    const amount =
      Number(req.body.amount);

    const method =
      String(req.body.method || "")
        .trim();

    const accountDetails =
      String(
        req.body.accountDetails || ""
      ).trim();

    const note =
      String(req.body.note || "")
        .trim();

    if (
      !Number.isFinite(amount) ||
      amount <= 0 ||
      !method ||
      !accountDetails
    ) {

      return res.status(400).json({
        error:
          "Valid amount, payment method and receiving details are required"
      });

    }

    try {

      const result = await query(

        `INSERT INTO withdrawals
        (
          user_id,
          amount,
          method,
          account_details,
          note
        )

        VALUES
        ($1,$2,$3,$4,$5)

        RETURNING
        id,
        amount,
        method,
        status,
        created_at`,

        [
          req.user.userId,
          amount,
          method,
          accountDetails,
          note
        ]

      );

      res.status(201).json({

        message:
          "Withdrawal request submitted for review",

        withdrawal:
          result.rows[0]

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to submit withdrawal"
      });

    }

  }
);


/* =========================
   WITHDRAWAL HISTORY
========================= */

app.get(
  "/api/withdrawals",
  auth,
  async (req, res) => {

    try {

      const result = await query(

        `SELECT
        id,
        amount,
        method,
        status,
        created_at

        FROM withdrawals

        WHERE user_id=$1

        ORDER BY created_at DESC`,

        [req.user.userId]

      );

      res.json({
        withdrawals:
          result.rows
      });

    } catch (error) {

      res.status(500).json({
        error:
          "Unable to load withdrawals"
      });

    }

  }
);


/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {

    console.log(
      `API running on port ${PORT}`
    );

  }
);
