const {
  getPool,
  requireConfig,
  verifyPassword,
  encodeSession,
  sessionCookie,
} = require('./core-auth-lib');

function maskIdentifier(value) {
  const id = String(value || '').trim();
  if (!id) return 'empty';
  const [local = '', domain = ''] = id.split('@');
  if (!domain) {
    return `${local.slice(0, 2)}***`;
  }
  return `${local.slice(0, 2)}***@${domain}`;
}

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

  const identifier = String(body?.email || '').trim();
  const password = String(body?.password || '');

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const pool = getPool(config);
    const { rows: colRows } = await pool.query(
      `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'core_users'
      `
    );

    const columns = new Set(colRows.map((row) => row.column_name));
    const candidates = ['email', 'userid', 'user_id', 'username'];
    const available = candidates.filter((name) => columns.has(name));

    if (available.length === 0) {
      return res.status(500).json({ error: 'Core users table is missing a login identifier column.' });
    }

    const where = available.map((name) => `lower(${name}) = lower($1)`).join(' OR ');
    const { rows } = await pool.query(
      `SELECT email, password_hash FROM core_users WHERE ${where} LIMIT 1`,
      [identifier]
    );

    const user = rows[0];
    if (!user) {
      console.info('Core login denied: user_not_found', {
        identifier: maskIdentifier(identifier),
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (!verifyPassword(password, user.password_hash)) {
      console.info('Core login denied: password_mismatch', {
        identifier: maskIdentifier(identifier),
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    console.info('Core login success', {
      identifier: maskIdentifier(user.email || identifier),
    });

    const token = encodeSession(user.email, config.secret);
    res.setHeader('Set-Cookie', sessionCookie(token));
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Core login error:', err);
    return res.status(500).json({ error: 'Server error. Please try again later.' });
  }
};
