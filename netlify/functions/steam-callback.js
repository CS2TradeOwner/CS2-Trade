
const {
  STATE_COOKIE,
  SESSION_COOKIE,
  cookieValue,
  cookie,
  clearCookie,
  createSession,
  siteOrigin
} = require('./_auth');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const origin = (() => {
    try { return siteOrigin(event); }
    catch (_) { return ''; }
  })();

  const fail = (reason) => ({
    statusCode: 302,
    headers: {
      Location: `${origin || '/'}?steam_error=${encodeURIComponent(reason)}#profile`,
      'Set-Cookie': clearCookie(STATE_COOKIE),
      'Cache-Control': 'no-store'
    },
    body: ''
  });

  try {
    const params = new URLSearchParams(event.rawQuery || '');
    const state = params.get('state');
    const expectedState = cookieValue(event, STATE_COOKIE);

    if (!state || !expectedState || state !== expectedState)
      return fail('state_check_failed');

    if (params.get('openid.mode') !== 'id_res')
      return fail('steam_auth_cancelled');

    const callback = new URL('/.netlify/functions/steam-callback', origin);
    callback.searchParams.set('state', state);

    if (params.get('openid.return_to') !== callback.toString())
      return fail('return_url_mismatch');

    if (params.get('openid.op_endpoint') !== 'https://steamcommunity.com/openid/login')
      return fail('unexpected_steam_endpoint');

    const signed = (params.get('openid.signed') || '').split(',');

    for (const field of ['op_endpoint', 'claimed_id', 'identity', 'return_to', 'response_nonce']) {
      if (!signed.includes(field)) return fail('required_field_not_signed');
    }

    const nonce = params.get('openid.response_nonce') || '';
    const nonceTime = Date.parse(nonce.slice(0, 20));

    if (!Number.isFinite(nonceTime) ||
        Math.abs(Date.now() - nonceTime) > 5 * 60 * 1000)
      return fail('stale_steam_assertion');

    const claimed = params.get('openid.claimed_id') || '';
    const identity = params.get('openid.identity') || '';
    const match = claimed.match(/^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/);

    if (!match || identity !== claimed)
      return fail('invalid_steam_identity');

    const steamId = match[1];
    const verify = new URLSearchParams();

    for (const [key, value] of params.entries()) {
      if (key.startsWith('openid.')) verify.append(key, value);
    }

    verify.set('openid.mode', 'check_authentication');

    const response = await fetch(
      'https://steamcommunity.com/openid/login',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded'
        },
        body: verify.toString()
      }
    );

    const result = await response.text();

    if (!response.ok || !/^is_valid:true\s*$/m.test(result))
      return fail('steam_assertion_invalid');

    if (!process.env.OWNER_STEAM_ID64 ||
        !/^\d{17}$/.test(process.env.OWNER_STEAM_ID64))
      return fail('owner_id_not_configured');

    const session = createSession(steamId);

    return {
      statusCode: 302,
      headers: {
        Location: `${origin}/?steam=connected#profile`,
        'Cache-Control': 'no-store'
      },
      multiValueHeaders: {
        'Set-Cookie': [
          cookie(SESSION_COOKIE, session, 60 * 60 * 12),
          clearCookie(STATE_COOKIE)
        ]
      },
      body: ''
    };
  } catch (_) {
    return fail('steam_callback_error');
  }
};
