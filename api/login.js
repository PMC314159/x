import {
  nonce,
  timestamp,
  signOAuth1,
  authHeader
} from "./_oauth1.js";

export default async function handler(req, res) {
  const consumerKey = process.env.X_API_KEY;
  const consumerSecret = process.env.X_API_SECRET;
  const callbackUrl = process.env.X_REDIRECT_URI;

  if (!consumerKey || !consumerSecret || !callbackUrl) {
    return res.status(500).send(
      "Missing X_API_KEY, X_API_SECRET, or X_REDIRECT_URI."
    );
  }

  const url = "https://api.x.com/oauth/request_token";

  const oauthParams = {
    oauth_callback: callbackUrl,
    oauth_consumer_key: consumerKey,
    oauth_nonce: nonce(),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: timestamp(),
    oauth_version: "1.0"
  };

  oauthParams.oauth_signature = signOAuth1({
    method: "POST",
    url,
    oauthParams,
    consumerSecret
  });

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: authHeader(oauthParams)
    }
  });

  const text = await response.text();

  if (!response.ok) {
    console.error("request_token failed:", text);
    return res.status(response.status).send(text);
  }

  const data = new URLSearchParams(text);

  const requestToken = data.get("oauth_token");
  const requestTokenSecret = data.get("oauth_token_secret");
  const confirmed = data.get("oauth_callback_confirmed");

  if (
    !requestToken ||
    !requestTokenSecret ||
    confirmed !== "true"
  ) {
    return res.status(500).send(
      "Invalid request token response from X."
    );
  }

  res.setHeader("Set-Cookie", [
    `x_oauth1_token=${encodeURIComponent(requestToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    `x_oauth1_secret=${encodeURIComponent(requestTokenSecret)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  ]);

  return res.redirect(
    `https://api.x.com/oauth/authorize?oauth_token=${encodeURIComponent(requestToken)}`
  );
}
