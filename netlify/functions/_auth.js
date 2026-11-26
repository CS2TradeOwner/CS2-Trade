
const crypto = require('node:crypto');

const SESSION_COOKIE = 'cs2trade_session';
const STATE_COOKIE = 'cs2trade_oauth_state';
const SESSION_TTL = 60 * 60 * 12;

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(value) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 characters');
  }
  return crypto.createHmac('sha256', secret)
    .update(value).digest('base64url');
}

function cookieValue(event, name) {
  const header = event.headers.cookie || event.headers.Cookie || '';
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return null;
}

function makeCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function createSession(steamId) {
  const payload = b64url(JSON.stringify({
    steamId,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL
  }));
  return `${payload}.${sign(payload)}`;
}

function readSession(event) {
  try {
    const token = cookieValue(event, SESSION_COOKIE);
    if (!token) return null;

    const [payload, signature] = token.split('.');
    if (!payload || !signature) return null;

    const expected = Buffer.from(sign(payload));
    const actual = Buffer.from(signature);

    if (expected.length !== actual.length ||
        !crypto.timingSafeEqual(expected, actual)) return null;

    const data = JSON.parse(
      Buffer.from(payload, 'base64url').toString('utf8')
    );

    if (!data.steamId ||
        !Number.isInteger(data.exp) ||
        data.exp < Date.now() / 1000) return null;

    return data;
  } catch (_) {
    return null;
  }
}

function json(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers
    },
    body: JSON.stringify(body)
  };
}

function siteOrigin(event) {
  if (process.env.URL) {
    return process.env.URL.replace(/\/$/, '');
  }

  const proto = (event.headers['x-forwarded-proto'] || 'https')
    .split(',')[0].trim();

  const host = (
    event.headers['x-forwarded-host'] ||
    event.headers.host || ''
  ).split(',')[0].trim();

  if (!host) throw new Error('Cannot determine site host');

  return `${proto}://${host}`;
}

module.exports = {
  SESSION_COOKIE,
  STATE_COOKIE,
  SESSION_TTL,
  b64url,
  sign,
  cookieValue,
  makeCookie,
  clearCookie,
  createSession,
  readSession,
  json,
  siteOrigin
};
