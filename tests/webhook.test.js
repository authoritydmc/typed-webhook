const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const {
  verifyGitHubWebhook,
  verifyStripeWebhook,
  verifyShopifyWebhook,
} = require('../src/index');

test('verifyGitHubWebhook validates authentic signature and rejects altered payloads', () => {
  const secret = 'super-secret-github-key';
  const payload = JSON.stringify({ action: 'opened', issue: { id: 1 } });
  const sig = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

  assert.strictEqual(verifyGitHubWebhook({ payload, signatureHeader: sig, secret }), true);
  assert.strictEqual(verifyGitHubWebhook({ payload: 'tampered', signatureHeader: sig, secret }), false);
  assert.strictEqual(verifyGitHubWebhook({ payload, signatureHeader: 'sha256=invalid', secret }), false);
});

test('verifyStripeWebhook validates signature and timestamp header', () => {
  const secret = 'whsec_test_secret';
  const payload = JSON.stringify({ type: 'payment_intent.succeeded' });
  const timestamp = Math.floor(Date.now() / 1000);
  const signedPayload = `${timestamp}.${payload}`;
  const sig = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
  const signatureHeader = `t=${timestamp},v1=${sig}`;

  assert.strictEqual(verifyStripeWebhook({ payload, signatureHeader, secret }), true);
  assert.strictEqual(verifyStripeWebhook({ payload: 'tampered', signatureHeader, secret }), false);
});

test('verifyShopifyWebhook validates Base64 HMAC signature', () => {
  const secret = 'shopify-app-secret';
  const payload = JSON.stringify({ id: 12345, total_price: '99.00' });
  const signatureHeader = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('base64');

  assert.strictEqual(verifyShopifyWebhook({ payload, signatureHeader, secret }), true);
  assert.strictEqual(verifyShopifyWebhook({ payload, signatureHeader: 'invalid_base64==', secret }), false);
});
