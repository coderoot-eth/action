'use strict';

const http = require('http');
const https = require('https');

const TRANSIENT_STATUS = new Set([429, 500, 502, 503, 504]);
const TRANSIENT_NETWORK = new Set(['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN']);

function timeoutError() {
  return Object.assign(new Error('HTTP deadline reached'), { code: 'ETIMEDOUT' });
}

/** One attempt, including response-body delivery, under an absolute timeout. */
function request(url, { method = 'GET', headers = {}, body, timeoutMs = 30000 } = {}) {
  const target = new URL(url);
  const driver = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = driver.request(target, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('aborted', () => reject(Object.assign(new Error('Response interrupted'), { code: 'ECONNRESET' })));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = text ? JSON.parse(text) : null; } catch {}
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, text });
      });
    });
    const timer = setTimeout(() => req.destroy(timeoutError()), timeoutMs);
    req.on('error', reject);
    req.on('close', () => clearTimeout(timer));
    if (body) req.write(body);
    req.end();
  });
}

function retryAfterMs(value, now) {
  if (typeof value !== 'string') return 0;
  if (/^\d+$/.test(value.trim())) return Number(value) * 1000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now) : 0;
}

/** Only opt in for a read or a write protected by the gate's idempotency contract. */
async function requestWithRetry(url, options, {
  timeoutMs = 30000, now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  random = Math.random, send = request,
} = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('HTTP timeout must be positive');
  const deadline = now() + timeoutMs;
  for (let attempt = 0; attempt < 3; attempt++) {
    const remaining = deadline - now();
    if (remaining <= 0) throw timeoutError();
    let response, error;
    try { response = await send(url, { ...options, timeoutMs: remaining }); }
    catch (caught) {
      if (!TRANSIENT_NETWORK.has(caught.code)) throw caught;
      error = caught;
    }
    if (now() >= deadline) throw timeoutError();
    if (response && !TRANSIENT_STATUS.has(response.status)) return response;
    if (attempt === 2) {
      if (error) throw error;
      return response;
    }
    const backoff = 1000 * 2 ** attempt * (0.5 + random() / 2);
    const delay = Math.max(backoff, retryAfterMs(response?.headers?.['retry-after'], now()));
    // Never shorten Retry-After to squeeze another request inside the deadline.
    if (delay >= deadline - now()) {
      if (error) throw error;
      return response;
    }
    await sleep(delay);
  }
}

module.exports = { request, requestWithRetry };
