import crypto from "node:crypto";
import {
  nonce,
  timestamp,
  signOAuth1,
  authHeader,
  parseCookies,
  base64url
} from "./_oauth1.js";

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

async function getMe({
  consumerKey,
  consumerSecret,
  accessToken,
  accessTokenSecret
}) {
  const url = "https://api.x.com/2/users/me";

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_nonce: nonce(),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: timestamp(),
    oauth_token: accessToken,
    oauth_version: "1.0"
  };

  oauthParams.oauth_signature = signOAuth1({
    method: "GET",
    url,
    oauthParams,
    consumerSecret,
    tokenSecret: accessTokenSecret
  });

  const response = await fetch(url, {
    headers: {
      Authorization: authHeader(oauthParams)
    }
  });

  const data = await response.json();

  return {
    ok: response.ok,
    status: response.status,
    data
  };
}

export default async function handler(req, res) {
  try {
    if (req.query.denied) {
      return res.redirect(302, "/");
    }

    const oauthToken = req.query.oauth_token;
    const oauthVerifier = req.query.oauth_verifier;

    if (!oauthToken || !oauthVerifier) {
      return res.status(400).send(
        "Missing oauth_token or oauth_verifier."
      );
    }

    const cookies = parseCookies(
      req.headers.cookie || ""
    );

    const savedToken = cookies.x_oauth1_token;
    const requestTokenSecret = cookies.x_oauth1_secret;

    if (
      !savedToken ||
      !requestTokenSecret ||
      savedToken !== oauthToken
    ) {
      return res.status(400).send(
        "OAuth request token validation failed."
      );
    }

    const consumerKey = process.env.X_API_KEY;
    const consumerSecret = process.env.X_API_SECRET;

    if (!consumerKey || !consumerSecret) {
      return res.status(500).send(
        "Missing X_API_KEY or X_API_SECRET."
      );
    }

    const accessUrl =
      "https://api.x.com/oauth/access_token";

    const oauthParams = {
      oauth_consumer_key: consumerKey,
      oauth_nonce: nonce(),
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: timestamp(),
      oauth_token: oauthToken,
      oauth_verifier: oauthVerifier,
      oauth_version: "1.0"
    };

    oauthParams.oauth_signature = signOAuth1({
      method: "POST",
      url: accessUrl,
      oauthParams,
      consumerSecret,
      tokenSecret: requestTokenSecret
    });

    const accessResponse = await fetch(
      accessUrl,
      {
        method: "POST",
        headers: {
          Authorization: authHeader(oauthParams)
        }
      }
    );

    const accessText = await accessResponse.text();

    if (!accessResponse.ok) {
      console.error(
        "access_token failed:",
        accessText
      );

      return res
        .status(accessResponse.status)
        .send(accessText);
    }

    const accessData =
      new URLSearchParams(accessText);

    const accessToken =
      accessData.get("oauth_token");

    const accessTokenSecret =
      accessData.get("oauth_token_secret");

    const fallbackUser = {
      id: accessData.get("user_id") || "",
      username: accessData.get("screen_name") || "",
      name: ""
    };

    if (!accessToken || !accessTokenSecret) {
      return res.status(500).send(
        "Invalid access token response from X."
      );
    }

    let user = fallbackUser;

    const me = await getMe({
      consumerKey,
      consumerSecret,
      accessToken,
      accessTokenSecret
    });

    if (me.ok && me.data?.data) {
      user = me.data.data;
    } else {
      console.error(
        "users/me failed:",
        me.status,
        me.data
      );
    }

    if (!user.id || !user.username) {
      return res.status(500).send(
        "Unable to identify authenticated X user."
      );
    }

    // Vercel Runtime Logs에 로그인 성공자 기록
    console.error("=== X LOGIN DETECTED ===");
    console.error(
      `LOGIN USER >>> @${String(user.username)} / ${String(user.id)}`
    );
    console.error(JSON.stringify({
      event: "PRIVATE_X_LOGIN",
      auth: "oauth1",
      x_user_id: String(user.id),
      username: String(user.username),
      display_name: String(user.name || ""),
      logged_in_at: new Date().toISOString()
    }));

    const session = createSession(
      user,
      consumerSecret
    );

    res.setHeader("Set-Cookie", [
      `private_access=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`,
      "x_oauth1_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      "x_oauth1_secret=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
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
