const { clearSession, json } = require('./_auth');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST' && event.httpMethod !== 'GET') {
    return json(405, { error: 'method_not_allowed' });
  }

  try {
    clearSession(event);
    return json(200, { success: true, message: 'logged_out' });
  } catch (_) {
    return json(500, { error: 'server_error' });
  }
};
