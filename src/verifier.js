const crypto = require('crypto');

/**
 * Constant time string comparison to prevent timing attacks.
 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Verify GitHub Webhook signature (`sha256=...`)
 */
function verifyGitHubWebhook({ payload, signatureHeader, secret }) {
  if (!payload || !signatureHeader || !secret) return false;
  const expectedSig = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return timingSafeEqual(signatureHeader, expectedSig);
}

/**
 * Verify Stripe Webhook signature (`t=...,v1=...`)
 */
function verifyStripeWebhook({ payload, signatureHeader, secret, toleranceSeconds = 300 }) {
  if (!payload || !signatureHeader || !secret) return false;

  const parts = signatureHeader.split(',').reduce((acc, part) => {
    const [k, v] = part.split('=');
    if (k && v) acc[k.trim()] = v.trim();
    return acc;
  }, {});

  const timestamp = parts['t'];
  const sig = parts['v1'];
  if (!timestamp || !sig) return false;

  // Check timestamp freshness if tolerance is provided
  if (toleranceSeconds > 0) {
    const now = Math.floor(Date.now() / 1000);
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(now - ts) > toleranceSeconds) {
      return false;
    }
  }

  const signedPayload = `${timestamp}.${payload}`;
  const expectedSig = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
  return timingSafeEqual(sig, expectedSig);
}

/**
 * Verify Shopify Webhook signature (Base64 HMAC)
 */
function verifyShopifyWebhook({ payload, signatureHeader, secret }) {
  if (!payload || !signatureHeader || !secret) return false;
  const expectedSig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('base64');
  return timingSafeEqual(signatureHeader, expectedSig);
}

const PROVIDER_HEADERS = {
  github: 'x-hub-signature-256',
  stripe: 'stripe-signature',
  shopify: 'x-shopify-hmac-sha256',
};

/**
 * Universal webhook verifier routing to specific provider logic.
 */
function verifyWebhook({ provider, payload, signatureHeader, secret, toleranceSeconds = 300 }) {
  const normProvider = (provider || '').toLowerCase();
  switch (normProvider) {
    case 'github':
      return verifyGitHubWebhook({ payload, signatureHeader, secret });
    case 'stripe':
      return verifyStripeWebhook({ payload, signatureHeader, secret, toleranceSeconds });
    case 'shopify':
      return verifyShopifyWebhook({ payload, signatureHeader, secret });
    default:
      throw new Error(`Unsupported webhook provider: ${provider}`);
  }
}

module.exports = {
  timingSafeEqual,
  PROVIDER_HEADERS,
  verifyWebhook,
  verifyGitHubWebhook,
  verifyStripeWebhook,
  verifyShopifyWebhook,
};
