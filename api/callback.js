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

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createSession(user, secret) {
  const payload = {
    sub: String(user.id),
    username: String(user.username),
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12
  };

  const encodedPayload = base64url(
    JSON.stringify(payload)
  );

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encodedPayload)
    .digest("base64url");

  return `${encodedPayload}.${signature}`;
}

export default async function handler(req, res) {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(
        `X authorization failed: ${
          error_description || error
        }`
      );
    }

    if (!code || !state) {
      return res.status(400).send(
        "Missing authorization code or state."
      );
    }

    const cookies = parseCookies(
      req.headers.cookie || ""
    );

    const savedState = cookies.x_oauth_state;
    const codeVerifier = cookies.x_code_verifier;

    if (!savedState || state !== savedState) {
      return res.status(400).send(
        "OAuth state validation failed."
      );
    }

    if (!codeVerifier) {
      return res.status(400).send(
        "Missing PKCE code verifier."
      );
    }

    const clientId = process.env.X_CLIENT_ID;
    const clientSecret = process.env.X_CLIENT_SECRET;
    const redirectUri = process.env.X_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(500).send(
        "Missing X OAuth environment variables."
      );
    }

    const basicAuth = Buffer.from(
      `${clientId}:${clientSecret}`
    ).toString("base64");

    const tokenBody = new URLSearchParams({
      code,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    });

    const tokenResponse = await fetch(
      "https://api.x.com/2/oauth2/token",
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${basicAuth}`,
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: tokenBody
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error("Token exchange failed:", tokenData);

      return res.status(tokenResponse.status).json({
        step: "token_exchange",
        error: tokenData
      });
    }

    const accessToken = tokenData.access_token;

    const meResponse = await fetch(
      "https://api.x.com/2/users/me",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const meData = await meResponse.json();

    if (!meResponse.ok || !meData?.data) {
      console.error("User lookup failed:", meData);

      return res.status(meResponse.status || 500).json({
        step: "user_lookup",
        error: meData
      });
    }

    const session = createSession(
      meData.data,
      clientSecret
    );

    res.setHeader("Set-Cookie", [
      `private_access=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`,
      "x_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      "x_code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    ]);

    return res.redirect(302, "/secret.html");
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Unexpected server error.",
      message: error.message
    });
  }
}
