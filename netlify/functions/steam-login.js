const crypto = require('node:crypto');
const { STATE_COOKIE, cookie, siteOrigin } = require('./_auth');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  try {
    const origin = siteOrigin(event);
    const state = crypto.randomBytes(24).toString('base64url');
    const callback = new URL('/.netlify/functions/steam-callback', origin);
    callback.searchParams.set('state', state);

    const params = new URLSearchParams({
      'openid.ns': 'http://specs.openid.net/auth/2.0',
      'openid.mode': 'checkid_setup',
      'openid.return_to': callback.toString(),
      'openid.realm': origin + '/',
      'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
      'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'
    });

    return {
      statusCode: 302,
      headers: {
        Location: `https://steamcommunity.com/openid/login?${params}`,
        'Set-Cookie': cookie(STATE_COOKIE, state, 600),
        'Cache-Control': 'no-store'
      },
      body: ''
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: 'Steam login is not configured. Check Netlify environment variables.'
    };
  }
};