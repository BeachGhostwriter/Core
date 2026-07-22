const {
  getPool,
  requireConfig,
  verifyPassword,
  encodeSession,
  sessionCookie,
} = require('./core-auth-lib');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const config = requireConfig(res);
  if (!config) {
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body || '{}');
    } catch {
      body = {};
    }
  }

  const email = String(body?.email || '').trim();
  const password = String(body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const pool = getPool(config);
    const { rows } = await pool.query(
      'SELECT email, password_hash FROM core_users WHERE lower(email) = lower($1)',
      [email]
    );

    const user = rows[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = encodeSession(user.email, config.secret);
    res.setHeader('Set-Cookie', sessionCookie(token));
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Core login error:', err);
    return res.status(500).json({ error: 'Server error. Please try again later.' });
  }
};
