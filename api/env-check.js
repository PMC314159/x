export default function handler(req, res) {
  const variables = {
    X_CLIENT_ID: process.env.X_CLIENT_ID,
    X_CLIENT_SECRET: process.env.X_CLIENT_SECRET,
    X_REDIRECT_URI: process.env.X_REDIRECT_URI,
    SECRET_X_HANDLE: process.env.SECRET_X_HANDLE
  };

  const result = {};

  for (const [name, value] of Object.entries(variables)) {
    result[name] = {
      present: Boolean(value),
      length: value ? value.length : 0
    };
  }

  res.status(200).json({
    environment: process.env.VERCEL_ENV || null,
    variables: result
  });
}
