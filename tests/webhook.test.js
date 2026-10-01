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

test('createExpressMiddleware attaches verified webhook on authentic signature', async () => {
  const { createExpressMiddleware } = require('../src/index');
  const secret = 'express-stripe-secret';
  const payloadObj = { event: 'invoice.paid' };
  const rawBody = JSON.stringify(payloadObj);
  const timestamp = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');

  const middleware = createExpressMiddleware({
    provider: 'stripe',
    secret,
  });

  const req = {
    headers: {
      'stripe-signature': `t=${timestamp},v1=${sig}`,
    },
    rawBody,
  };
  const res = {
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.data = data;
    },
  };

  let nextCalled = false;
  await middleware(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(req.webhook.verified, true);
  assert.deepStrictEqual(req.webhook.payload, payloadObj);
});

test('createNextRouteHandler processes valid Web standard Request', async () => {
  const { createNextRouteHandler } = require('../src/index');
  const secret = 'nextjs-github-secret';
  const payload = JSON.stringify({ action: 'created' });
  const sig = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

  const routeHandler = createNextRouteHandler({
    provider: 'github',
    secret,
    handler: async ({ payload, provider }) => {
      return new Response(JSON.stringify({ ok: true, action: payload.action, provider }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    },
  });

  const request = new Request('https://example.com/api/webhooks/github', {
    method: 'POST',
    headers: {
      'x-hub-signature-256': sig,
      'Content-Type': 'application/json',
    },
    body: payload,
  });

  const response = await routeHandler(request);
  assert.strictEqual(response.status, 200);
  const resJson = await response.json();
  assert.strictEqual(resJson.ok, true);
  assert.strictEqual(resJson.action, 'created');
  assert.strictEqual(resJson.provider, 'github');
});

test('createHonoMiddleware verifies and populates context', async () => {
  const { createHonoMiddleware } = require('../src/index');
  const secret = 'hono-shopify-secret';
  const payload = JSON.stringify({ product: 'shoe', price: 50 });
  const sig = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('base64');

  const middleware = createHonoMiddleware({
    provider: 'shopify',
    secret,
  });

  const contextData = {};
  const mockContext = {
    req: {
      text: async () => payload,
      header: (name) => (name === 'x-shopify-hmac-sha256' ? sig : null),
    },
    set: (key, val) => {
      contextData[key] = val;
    },
    json: (data, status) => ({ data, status }),
  };

  let nextCalled = false;
  await middleware(mockContext, async () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(contextData.webhook.verified, true);
  assert.strictEqual(contextData.webhook.payload.product, 'shoe');
});

