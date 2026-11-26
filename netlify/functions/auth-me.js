const { readSession, json } = require('./_auth');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return json(405, { error: 'method_not_allowed' });
  }

  try {
    const session = readSession(event);

    if (!session) {
      return json(200, { authenticated: false });
    }

    const ownerId = process.env.OWNER_STEAM_ID64 || '';
    const role = session.steamId === ownerId ? 'owner' : 'user';

    return json(200, {
      authenticated: true,
      steamId: session.steamId,
      role
    });
  } catch (_) {
    return json(500, { error: 'server_not_configured' });
  }
};
