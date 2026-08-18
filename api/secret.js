import crypto from "node:crypto";

function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");

    if (!name) return;

    cookies[name] = decodeURIComponent(rest.join("="));
  });

  return cookies;
}

function decodeBase64url(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding =
    normalized.length % 4 === 0
      ? ""
      : "=".repeat(4 - (normalized.length % 4));

  return Buffer.from(
    normalized + padding,
    "base64"
  ).toString("utf8");
}

function verifySession(token, secret) {
  if (!token || !secret) return null;

  const [payloadPart, signaturePart] =
    token.split(".");

  if (!payloadPart || !signaturePart) {
    return null;
  }

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payloadPart)
    .digest("base64url");

  const actual = Buffer.from(signaturePart);
  const expected = Buffer.from(expectedSignature);

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      decodeBase64url(payloadPart)
    );

    if (
      !payload.exp ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  const clientSecret = process.env.X_CLIENT_SECRET;
  const handle = process.env.SECRET_X_HANDLE;

  if (!clientSecret || !handle) {
    return res.status(500).json({
      error:
        "Missing X_CLIENT_SECRET or SECRET_X_HANDLE."
    });
  }

  const cookies = parseCookies(
    req.headers.cookie || ""
  );

  const session = verifySession(
    cookies.private_access,
    clientSecret
  );

  if (!session) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  return res.status(200).json({
    handle,
    viewer: session.username
  });
}
