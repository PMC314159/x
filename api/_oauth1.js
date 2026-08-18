import crypto from "node:crypto";

export function percentEncode(value) {
  return encodeURIComponent(String(value))
    .replace(/[!'()*]/g, c =>
      "%" + c.charCodeAt(0).toString(16).toUpperCase()
    );
}

export function nonce() {
  return crypto.randomBytes(24).toString("hex");
}

export function timestamp() {
  return Math.floor(Date.now() / 1000).toString();
}

function normalizeUrl(rawUrl) {
  const u = new URL(rawUrl);
  return `${u.protocol}//${u.host}${u.pathname}`;
}

function collectParams(rawUrl, oauthParams, bodyParams = {}) {
  const u = new URL(rawUrl);
  const params = [];

  for (const [k, v] of u.searchParams.entries()) {
    params.push([k, v]);
  }

  for (const [k, v] of Object.entries(oauthParams)) {
    if (k !== "oauth_signature") {
      params.push([k, v]);
    }
  }

  for (const [k, v] of Object.entries(bodyParams)) {
    params.push([k, v]);
  }

  params.sort((a, b) => {
    const ak = percentEncode(a[0]);
    const bk = percentEncode(b[0]);

    if (ak !== bk) {
      return ak < bk ? -1 : 1;
    }

    const av = percentEncode(a[1]);
    const bv = percentEncode(b[1]);
    return av < bv ? -1 : av > bv ? 1 : 0;
  });

  return params
    .map(([k, v]) => `${percentEncode(k)}=${percentEncode(v)}`)
    .join("&");
}

export function signOAuth1({
  method,
  url,
  oauthParams,
  consumerSecret,
  tokenSecret = "",
  bodyParams = {}
}) {
  const normalizedParams = collectParams(
    url,
    oauthParams,
    bodyParams
  );

  const baseString = [
    method.toUpperCase(),
    percentEncode(normalizeUrl(url)),
    percentEncode(normalizedParams)
  ].join("&");

  const signingKey =
    `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret)}`;

  return crypto
    .createHmac("sha1", signingKey)
    .update(baseString)
    .digest("base64");
}

export function authHeader(oauthParams) {
  const entries = Object.entries(oauthParams)
    .filter(([k]) => k.startsWith("oauth_"))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(
      ([k, v]) =>
        `${percentEncode(k)}="${percentEncode(v)}"`
    );

  return `OAuth ${entries.join(", ")}`;
}

export function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");
    if (!name) return;
    cookies[name] = decodeURIComponent(rest.join("="));
  });

  return cookies;
}

export function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
