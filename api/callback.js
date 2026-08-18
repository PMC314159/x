function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, ...rest] = cookie.trim().split("=");

    if (!name) return;

    cookies[name] = decodeURIComponent(rest.join("="));
  });

  return cookies;
}

export default async function handler(req, res) {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(
        `X authorization failed: ${error}`
      );
    }

    if (!code || !state) {
      return res.status(400).send(
        "Missing authorization code or state."
      );
    }

    const cookies = parseCookies(req.headers.cookie);

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
      console.error("Token error:", tokenData);

      return res.status(500).json({
        step: "token_exchange",
        error: tokenData
      });
    }

    const accessToken = tokenData.access_token;

    const meResponse = await fetch(
      "https://api.x.com/2/users/me?user.fields=public_metrics",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const meData = await meResponse.json();

    if (!meResponse.ok) {
      console.error("User lookup error:", meData);

      return res.status(500).json({
        step: "user_lookup",
        error: meData
      });
    }

    const user = meData.data;

    res.setHeader("Set-Cookie", [
      "x_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      "x_code_verifier=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    ]);

    res.setHeader(
      "Content-Type",
      "text/html; charset=utf-8"
    );

    return res.status(200).send(`
<!doctype html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>X OAuth Test</title>
<style>
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  background: #000;
  color: #fff;
  font-family: Arial, sans-serif;
}
main {
  text-align: center;
}
.ok {
  font-size: 14px;
  opacity: .6;
  margin-bottom: 20px;
}
.username {
  font-size: 34px;
  font-weight: 700;
}
.info {
  margin-top: 12px;
  opacity: .7;
  line-height: 1.7;
}
</style>
</head>
<body>
<main>
  <div class="ok">X OAUTH SUCCESS</div>
  <div class="username">@${user.username}</div>

  <div class="info">
    ${user.name}<br>
    User ID: ${user.id}<br>
    Followers: ${user.public_metrics?.followers_count ?? "-"}<br>
    Following: ${user.public_metrics?.following_count ?? "-"}
  </div>
</main>
</body>
</html>
    `);

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Unexpected server error.",
      message: error.message
    });
  }
}
