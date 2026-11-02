const { prisma } = require("./db");
const { newSessionId, expiresAt, publicUser } = require("./utils");

async function createSession(userId) {
  const id = newSessionId();

  await prisma.session.create({
    data: {
      id,
      userId,
      expiresAt: expiresAt(),
    },
  });

  return id;
}

async function getSessionWithUser(id) {
  const session = await prisma.session.findUnique({
    where: { id },
    include: {
      user: {
        select: {
          id: true,
          email: true,
        },
      },
    },
  });

  // Session does not exist
  if (!session) {
    return null;
  }

  // Check whether the session has expired
  if (session.expiresAt <= new Date()) {
    await deleteSession(id);
    return null;
  }

  return {
    ...session,
    user: publicUser(session.user),
  };
}

async function deleteSession(id) {
  await prisma.session.deleteMany({
    where: { id },
  });
}

async function deleteAllUserSessions(userId) {
  const result = await prisma.session.deleteMany({
    where: { userId },
  });

  return result.count;
}

module.exports = {
  createSession,
  getSessionWithUser,
  deleteSession,
  deleteAllUserSessions,
};
