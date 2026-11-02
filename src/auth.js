const { SESSION_COOKIE, cookieOptions } = require("./utils");
const { getSessionWithUser } = require("./session");

async function requireAuth(req, res, next) {
  try {
    // Read the session ID from the cookie
    const sessionId = req.cookies?.[SESSION_COOKIE];

    // Check whether the cookie exists
    if (!sessionId) {
      return res.status(401).json({
        error: "Not logged in",
      });
    }

    // Look up the session in the database
    const session = await getSessionWithUser(sessionId);

    // Check whether the session is valid
    if (!session) {
      res.clearCookie(SESSION_COOKIE, cookieOptions);

      return res.status(401).json({
        error: "Invalid or expired session",
      });
    }

    // Attach authenticated user information to the request
    req.user = session.user;
    req.sessionId = session.id;

    // Allow the request to continue
    return next();
  } catch (error) {
    console.error("Authentication middleware error:", error);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
}

module.exports = { requireAuth };
