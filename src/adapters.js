/**
 * Framework adapters for Express, Next.js (App & Pages Router), and Hono.
 */

const {
  verifyWebhook,
  PROVIDER_HEADERS,
} = require('./verifier');


/**
 * Creates an Express middleware for webhook verification.
 * Supports raw buffers, string bodies, or pre-configured body-parsers.
 */
function createExpressMiddleware(options) {
  const {
    provider,
    secret,
    headerName = PROVIDER_HEADERS[provider],
    toleranceSeconds = 300,
    onError = (err, req, res) => res.status(400).json({ error: err.message }),
  } = options;

  return async function expressWebhookMiddleware(req, res, next) {
    try {
      let rawBody = '';

      if (req.rawBody) {
        rawBody = typeof req.rawBody === 'string' ? req.rawBody : req.rawBody.toString('utf8');
      } else if (Buffer.isBuffer(req.body)) {
        rawBody = req.body.toString('utf8');
      } else if (typeof req.body === 'string') {
        rawBody = req.body;
      } else if (req.body && typeof req.body === 'object') {
        rawBody = JSON.stringify(req.body);
      } else if (typeof req.on === 'function') {
        // Stream raw body chunks if unparsed
        const chunks = [];
        for await (const chunk of req) {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        }
        rawBody = Buffer.concat(chunks).toString('utf8');
      }

      const sigHeader = req.headers[headerName.toLowerCase()] || req.headers[headerName];

      if (!sigHeader) {
        throw new Error(`Missing required signature header: ${headerName}`);
      }

      const isValid = verifyWebhook({
        provider,
        payload: rawBody,
        signatureHeader: sigHeader,
        secret: typeof secret === 'function' ? await secret(req) : secret,
        toleranceSeconds,
      });

      if (!isValid) {
        throw new Error(`Invalid webhook signature for provider: ${provider}`);
      }

      let parsedPayload = null;
      try {
        parsedPayload = JSON.parse(rawBody);
      } catch (_) {
        parsedPayload = rawBody;
      }

      req.webhook = {
        provider,
        rawBody,
        payload: parsedPayload,
        verified: true,
      };

      next();
    } catch (err) {
      onError(err, req, res);
    }
  };
}

/**
 * Creates a Next.js App Router (or standard Web Request/Response) POST handler.
 */
function createNextRouteHandler(options) {
  const {
    provider,
    secret,
    headerName = PROVIDER_HEADERS[provider],
    toleranceSeconds = 300,
    handler,
    onError = (err) => new Response(JSON.stringify({ error: err.message }), { status: 400, headers: { 'Content-Type': 'application/json' } }),
  } = options;

  return async function handleNextWebhook(request) {
    try {
      const rawBody = await request.text();
      const sigHeader = request.headers.get(headerName.toLowerCase()) || request.headers.get(headerName);

      if (!sigHeader) {
        throw new Error(`Missing required signature header: ${headerName}`);
      }

      const resolvedSecret = typeof secret === 'function' ? await secret(request) : secret;
      const isValid = verifyWebhook({
        provider,
        payload: rawBody,
        signatureHeader: sigHeader,
        secret: resolvedSecret,
        toleranceSeconds,
      });

      if (!isValid) {
        throw new Error(`Invalid webhook signature for provider: ${provider}`);
      }

      let parsedPayload = null;
      try {
        parsedPayload = JSON.parse(rawBody);
      } catch (_) {
        parsedPayload = rawBody;
      }

      if (handler) {
        return await handler({
          provider,
          rawBody,
          payload: parsedPayload,
          request,
        });
      }

      return new Response(JSON.stringify({ received: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err) {
      return onError(err, request);
    }
  };
}

/**
 * Creates a Hono middleware for webhook verification.
 */
function createHonoMiddleware(options) {
  const {
    provider,
    secret,
    headerName = PROVIDER_HEADERS[provider],
    toleranceSeconds = 300,
    onError = (err, c) => c.json({ error: err.message }, 400),
  } = options;

  return async function honoWebhookMiddleware(c, next) {
    try {
      const rawBody = await c.req.text();
      const sigHeader = c.req.header(headerName.toLowerCase()) || c.req.header(headerName);

      if (!sigHeader) {
        throw new Error(`Missing required signature header: ${headerName}`);
      }

      const resolvedSecret = typeof secret === 'function' ? await secret(c) : secret;
      const isValid = verifyWebhook({
        provider,
        payload: rawBody,
        signatureHeader: sigHeader,
        secret: resolvedSecret,
        toleranceSeconds,
      });

      if (!isValid) {
        throw new Error(`Invalid webhook signature for provider: ${provider}`);
      }

      let parsedPayload = null;
      try {
        parsedPayload = JSON.parse(rawBody);
      } catch (_) {
        parsedPayload = rawBody;
      }

      c.set('webhook', {
        provider,
        rawBody,
        payload: parsedPayload,
        verified: true,
      });

      await next();
    } catch (err) {
      return onError(err, c);
    }
  };
}

module.exports = {
  createExpressMiddleware,
  createNextRouteHandler,
  createHonoMiddleware,
};
