# 🪝 typed-webhook

**Multi-Provider Webhook Signature Verifier and Type-Safe Payload Handler**

Verify incoming webhook signatures across Stripe, GitHub, Shopify, and Clerk with unified, zero-dependency cryptographic utilities.

---

## ✨ Supported Providers

- 💳 **Stripe** (`stripe-signature` timestamp + HMAC-SHA256)
- 🐙 **GitHub** (`x-hub-signature-256` HMAC-SHA256)
- 🛍️ **Shopify** (`x-shopify-hmac-sha256` base64 HMAC)
- 🔐 **Clerk / Svix** (`svix-signature` HMAC)

---

## 🚀 Quickstart

```javascript
const { verifyGitHubWebhook, verifyStripeWebhook } = require('typed-webhook');

// GitHub Webhook Handler
const isValid = verifyGitHubWebhook({
  payload: rawRequestBodyString,
  signatureHeader: req.headers['x-hub-signature-256'],
  secret: process.env.GITHUB_WEBHOOK_SECRET,
});

if (!isValid) {
  return res.status(401).send('Invalid signature');
}
```

---

## 📄 License

MIT License.
