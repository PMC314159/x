export default function handler(req, res) {
  res.setHeader(
    "Set-Cookie",
    "private_access=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  );

  return res.status(204).end();
}
