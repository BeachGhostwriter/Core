const {
  requireConfig,
  isAuthenticated,
  parseCookies,
  COOKIE_NAME,
  decodeAndValidateSession,
} = require('./core-auth-lib');

module.exports = async function handler(req, res) {
  const config = requireConfig(res);
  if (!config) {
    return;
  }

  if (!isAuthenticated(req, config)) {
    return res.status(200).json({ authenticated: false });
  }

  const cookies = parseCookies(req);
  const payload = decodeAndValidateSession(cookies[COOKIE_NAME], config.secret);
  return res.status(200).json({ authenticated: true, email: payload.email });
};
