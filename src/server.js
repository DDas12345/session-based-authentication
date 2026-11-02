require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const { prisma } = require("./db");
const {
  SESSION_COOKIE,
  cookieOptions,
  normalizeEmail,
  publicUser,
} = require("./utils");
const {
  createSession,
  deleteSession,
  deleteAllUserSessions,
} = require("./session");
const { requireAuth } = require("./auth");
const app = express();
app.use(express.json());
app.use(cookieParser());
app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    // 1. Validate email and password
    if (
      typeof email !== "string" ||
      !email.includes("@") ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: "Invalid email or password",
      });
    }

    // 2. Normalize the email
    const normalizedEmail = normalizeEmail(email);

    // 3. Check whether the email already exists
    const existingUser = await prisma.user.findUnique({
      where: {
        email: normalizedEmail,
      },
    });

    if (existingUser) {
      return res.status(409).json({
        error: "Email already registered",
      });
    }

    // 4. Create the user
    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });

    // 5. Return the new user without the password
    return res.status(201).json(user);

  } catch (error) {
    console.error("Registration error:", error);

    if (error.code === "P2002") {
      return res.status(409).json({
        error: "Email already registered",
      });
    }

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    // 1. Read email and password
    const { email, password } = req.body ?? {};

    // 2. Validate input
    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    // 3. Normalize email
    const normalizedEmail = normalizeEmail(email);

    // 4. Find user in database
    const user = await prisma.user.findUnique({
      where: {
        email: normalizedEmail,
      },
    });

    // 5. Verify credentials
    if (!user || user.password !== password) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    // 6. Check for an existing session cookie
    const oldSessionId = req.cookies[SESSION_COOKIE];

    // 7. Delete old session if it exists
    if (oldSessionId) {
      await deleteSession(oldSessionId);
    }

    // 8. Create a new session
    const sessionId = await createSession(user.id);

    // 9. Send session ID through cookie
    res.cookie(SESSION_COOKIE, sessionId, cookieOptions);

    // 10. Return public user details
    return res.status(200).json({
      user: publicUser(user),
    });

  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.get("/me", requireAuth, (req, res) => res.json({ user: req.user }));

app.post("/auth/logout", async (req, res) => {
  try {
    // Get the current session ID
    const sessionId = req.cookies[SESSION_COOKIE];

    // Delete the session if it exists
    if (sessionId) {
      await deleteSession(sessionId);
    }

    // Clear the browser cookie
    res.clearCookie(SESSION_COOKIE, cookieOptions);

    // Return 204 No Content
    return res.status(204).send();

  } catch (error) {
    console.error("Logout error:", error);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/auth/logout-all", requireAuth, async (req, res) => {
  try {
    // 1. Delete all sessions belonging to this user
    const deletedCount = await deleteAllUserSessions(req.user.id);

    // 2. Clear the current browser's cookie
    res.clearCookie(SESSION_COOKIE, cookieOptions);

    // 3. Return the number of deleted sessions
    return res.status(200).json({
      loggedOutSessions: deletedCount,
    });

  } catch (error) {
    console.error("Logout all error:", error);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

const PORT = process.env.PORT ?? 3000;
if (require.main === module)
  app.listen(PORT, () =>
    console.log(`Server running on http://localhost:${PORT}`),
  );
module.exports = { app };
