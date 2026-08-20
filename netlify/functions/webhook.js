// netlify/functions/webhook.js
//
// Rapid Gateway calls THIS endpoint automatically when a payment succeeds
// (or fails). Use it to unlock premium access for the user.
//
// SECURITY: Rapid Gateway signs each webhook. Check their docs for the
// exact header name (likely "X-Rapid-Signature") before trusting payloads.

const crypto = require("crypto");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  try {
    const signature = event.headers["x-rapid-signature"];
    const secret = process.env.RAPID_GATEWAY_WEBHOOK_SECRET;

    if (secret && signature) {
      const expected = crypto
        .createHmac("sha256", secret)
        .update(event.body)
        .digest("hex");

      if (expected !== signature) {
        return { statusCode: 401, body: "Invalid signature" };
      }
    }

    const payload = JSON.parse(event.body || "{}");

    const status = payload.status;
    const customerEmail = payload.customer_email;
    const amount = payload.amount;

    if (status === "succeeded") {
      console.log(`Payment succeeded: ${customerEmail}, amount: ${amount}`);
    }

    return { statusCode: 200, body: JSON.stringify({ received: true }) };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Internal error", message: err.message }),
    };
  }
};
