const crypto = require("crypto");

// Next.js API route config: raw body erişimi için bodyParser kapalı olmalı.
// Vercel bu klasörü Next API route olarak ele alıyorsa gerekli.
exports.config = {
  api: {
    bodyParser: false,
  },
};

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function headerString(req, name) {
  const v = req.headers[name];
  if (v == null) return undefined;
  return Array.isArray(v) ? v[0] : v;
}

function verifyMetaSignature(rawBody, signatureHeader, appSecret) {
  if (!signatureHeader || !appSecret) {
    return false;
  }

  const expected = `sha256=${crypto
    .createHmac("sha256", appSecret)
    .update(rawBody)
    .digest("hex")}`;

  const signatureBuffer = Buffer.from(signatureHeader);
  const expectedBuffer = Buffer.from(expected);

  if (signatureBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
}

/** One JSON line per event — search Vercel Runtime Logs for `svc":"meta-webhook"` */
function emitRequestLog(payload) {
  process.stdout.write(
    `${JSON.stringify({ ts: new Date().toISOString(), ...payload })}\n`
  );
}

function safeRequestHeaders(req) {
  return {
    host: headerString(req, "host"),
    userAgent: headerString(req, "user-agent"),
    contentType: headerString(req, "content-type"),
    contentLength: headerString(req, "content-length"),
    forwardedFor: headerString(req, "x-forwarded-for"),
    vercelId: headerString(req, "x-vercel-id"),
    vercelDeploymentId: headerString(req, "x-vercel-deployment-id"),
    hasXHubSignature256: Boolean(headerString(req, "x-hub-signature-256")),
  };
}

async function airtableRecordExists(leadgenId) {
  const formula = encodeURIComponent(`{Leadgen ID}='${leadgenId}'`);
  const url = `https://api.airtable.com/v0/${process.env.BASE_ID}/Leads?maxRecords=1&filterByFormula=${formula}`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env.AIRTABLE_KEY}`,
    },
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(`Airtable lookup failed: ${JSON.stringify(data)}`);
  }

  return Array.isArray(data.records) && data.records.length > 0;
}

async function handler(req, res) {
  const reqId = crypto.randomBytes(8).toString("hex");
  const t0 = Date.now();
  const pathOnly = String(req.url || "/").split("?")[0];

  res.once("finish", () => {
    emitRequestLog({
      svc: "meta-webhook",
      event: "response_sent",
      reqId,
      method: req.method,
      path: pathOnly,
      statusCode: res.statusCode,
      ms: Date.now() - t0,
    });
  });

  emitRequestLog({
    svc: "meta-webhook",
    event: "request_received",
    reqId,
    method: req.method,
    path: pathOnly,
    queryParamKeys: Object.keys(req.query || {}),
    headers: safeRequestHeaders(req),
    ms: 0,
  });

  // 1) Meta webhook doğrulaması (GET)
  if (req.method === "GET") {
    // Meta query param isimleri noktalar içerdiği için bazı framework'ler
    // bunları farklı parse edebiliyor (nested vs flat). İkisini de destekle.
    const hub = req.query?.hub || {};
    const challenge =
      req.query?.["hub.challenge"] ?? hub["challenge"] ?? hub.challenge;
    const token =
      req.query?.["hub.verify_token"] ?? hub["verify_token"] ?? hub.verify_token;

    const verifyMatch =
      String(token ?? "").trim() ===
      String(process.env.VERIFY_TOKEN ?? "").trim();
    emitRequestLog({
      svc: "meta-webhook",
      event: "get_webhook_handshake",
      reqId,
      hasChallenge: challenge != null && String(challenge).length > 0,
      hasVerifyTokenParam: Boolean(token && String(token).length > 0),
      verifyTokenMatch: verifyMatch,
      envVerifyTokenConfigured: Boolean(
        String(process.env.VERIFY_TOKEN ?? "").trim()
      ),
      ms: Date.now() - t0,
    });

    if (verifyMatch) {
      // Meta plain-text bekler.
      return res.status(200).send(String(challenge ?? ""));
    }

    return res.status(403).send("Forbidden");
  }

  // 2) Gerçek lead geldiğinde (POST)
  if (req.method === "POST") {
    try {
      emitRequestLog({
        svc: "meta-webhook",
        event: "post_read_start",
        reqId,
        ms: Date.now() - t0,
      });

      const rawBody = await getRawBody(req);
      const signatureHeader = headerString(req, "x-hub-signature-256");
      emitRequestLog({
        svc: "meta-webhook",
        event: "post_body_read",
        reqId,
        rawBytes: rawBody.length,
        hasXHubSignature256: Boolean(signatureHeader),
        ms: Date.now() - t0,
      });

      const payload = JSON.parse(rawBody.toString("utf8"));
      const leadgenId = payload?.entry?.[0]?.changes?.[0]?.value?.leadgen_id;
      emitRequestLog({
        svc: "meta-webhook",
        event: "post_json_parsed",
        reqId,
        topLevelKeys: payload && typeof payload === "object" ? Object.keys(payload) : [],
        hasLeadgenId: Boolean(leadgenId),
        ms: Date.now() - t0,
      });

      if (!leadgenId) {
        // Meta "Verify and save" sırasında test POST atabilir.
        // Bu durumda `leadgen_id` gelmeyebileceği için imza doğrulaması yapmadan 200 dönmek doğrulamanın geçmesini sağlar.
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_no_leadgen_id_200",
          reqId,
          ms: Date.now() - t0,
        });
        return res.status(200).send("OK");
      }

      // Gerçek lead akışında imza doğrulaması şart (Meta: App Secret + ham gövde).
      // Vercel/Meta panellerinden kopyalanan secret'ta sık sık sonda \n veya boşluk kalır.
      const appSecret = String(process.env.META_APP_SECRET ?? "").trim();
      if (!appSecret) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_missing_meta_app_secret",
          reqId,
          ms: Date.now() - t0,
        });
        return res.status(500).json({
          error: "META_APP_SECRET is not configured on the server",
        });
      }

      const isValidSignature = verifyMetaSignature(
        rawBody,
        signatureHeader,
        appSecret
      );
      if (!isValidSignature) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_signature_invalid",
          reqId,
          hasXHubSignature256: Boolean(signatureHeader),
          rawBodyByteLength: rawBody.length,
          appSecretCharLength: appSecret.length,
          leadgenIdSuffix: String(leadgenId).slice(-8),
          ms: Date.now() - t0,
        });
        return res.status(401).json({ error: "Invalid webhook signature" });
      }

      emitRequestLog({
        svc: "meta-webhook",
        event: "post_signature_ok",
        reqId,
        ms: Date.now() - t0,
      });

      const alreadyExists = await airtableRecordExists(leadgenId);
      if (alreadyExists) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_duplicate_skip_airtable",
          reqId,
          ms: Date.now() - t0,
        });
        return res.status(200).json({ ok: true, duplicate: true });
      }

      // Graph API'den lead detaylarını çek
      const leadResponse = await fetch(
        `https://graph.facebook.com/${leadgenId}?access_token=${process.env.PAGE_TOKEN}`
      );
      const leadData = await leadResponse.json();

      if (!leadResponse.ok) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_graph_api_error",
          reqId,
          graphStatus: leadResponse.status,
          ms: Date.now() - t0,
        });
        return res.status(502).json({
          error: "Failed to fetch lead from Graph API",
          details: leadData,
        });
      }

      const fieldData = leadData.field_data || [];
      const getFieldValue = (name) =>
        fieldData.find((f) => f.name === name)?.values?.[0] || null;

      // Airtable'a yaz
      const airtableResponse = await fetch(
        `https://api.airtable.com/v0/${process.env.BASE_ID}/Leads`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.AIRTABLE_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            fields: {
              "Leadgen ID": leadgenId,
              "Ad Soyad": getFieldValue("full_name"),
              "E-posta": getFieldValue("email"),
              Telefon: getFieldValue("phone_number"),
            },
          }),
        }
      );

      const airtableResult = await airtableResponse.json();

      if (!airtableResponse.ok) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_airtable_write_error",
          reqId,
          airtableStatus: airtableResponse.status,
          ms: Date.now() - t0,
        });
        return res.status(502).json({
          error: "Failed to write to Airtable",
          details: airtableResult,
        });
      }

      emitRequestLog({
        svc: "meta-webhook",
        event: "post_success_200",
        reqId,
        ms: Date.now() - t0,
      });
      return res.status(200).send("OK");
    } catch (error) {
      emitRequestLog({
        svc: "meta-webhook",
        event: "post_uncaught_error",
        reqId,
        message: error?.message || String(error),
        ms: Date.now() - t0,
      });
      return res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  }

  emitRequestLog({
    svc: "meta-webhook",
    event: "method_not_allowed",
    reqId,
    method: req.method,
    ms: Date.now() - t0,
  });
  return res.status(405).json({ error: "Method not allowed" });
}

module.exports = handler;
