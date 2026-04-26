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
  // 1) Meta webhook doğrulaması (GET)
  if (req.method === "GET") {
    // Meta query param isimleri noktalar içerdiği için bazı framework'ler
    // bunları farklı parse edebiliyor (nested vs flat). İkisini de destekle.
    const hub = req.query?.hub || {};
    const challenge =
      req.query?.["hub.challenge"] ?? hub["challenge"] ?? hub.challenge;
    const token =
      req.query?.["hub.verify_token"] ?? hub["verify_token"] ?? hub.verify_token;

    if (String(token ?? "").trim() === String(process.env.VERIFY_TOKEN ?? "").trim()) {
      // Meta plain-text bekler.
      return res.status(200).send(String(challenge ?? ""));
    }

    return res.status(403).send("Forbidden");
  }

  // 2) Gerçek lead geldiğinde (POST)
  if (req.method === "POST") {
    try {
      // Vercel'de istek satırı ile aynı yerde görünmesi için stdout (console.log) kullan.
      console.log("[meta-webhook] POST start");

      const rawBody = await getRawBody(req);
      const signatureHeader = headerString(req, "x-hub-signature-256");
      console.log(
        "[meta-webhook] POST body",
        JSON.stringify({
          rawBytes: rawBody.length,
          hasXHubSignature256: Boolean(signatureHeader),
        })
      );

      const payload = JSON.parse(rawBody.toString("utf8"));
      const leadgenId = payload?.entry?.[0]?.changes?.[0]?.value?.leadgen_id;
      console.log(
        "[meta-webhook] POST parsed",
        JSON.stringify({ hasLeadgenId: Boolean(leadgenId) })
      );

      if (!leadgenId) {
        // Meta "Verify and save" sırasında test POST atabilir.
        // Bu durumda `leadgen_id` gelmeyebileceği için imza doğrulaması yapmadan 200 dönmek doğrulamanın geçmesini sağlar.
        console.log("[meta-webhook] POST exit 200 no_leadgen_id (signature skipped)");
        return res.status(200).send("OK");
      }

      // Gerçek lead akışında imza doğrulaması şart (Meta: App Secret + ham gövde).
      // Vercel/Meta panellerinden kopyalanan secret'ta sık sık sonda \n veya boşluk kalır.
      const appSecret = String(process.env.META_APP_SECRET ?? "").trim();
      if (!appSecret) {
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
        console.log(
          "[meta-webhook] signature_verify_failed",
          JSON.stringify({
            hasXHubSignature256: Boolean(signatureHeader),
            rawBodyByteLength: rawBody.length,
            appSecretCharLength: appSecret.length,
            leadgenIdSuffix: String(leadgenId).slice(-8),
          })
        );
        return res.status(401).json({ error: "Invalid webhook signature" });
      }

      console.log("[meta-webhook] POST signature ok");

      const alreadyExists = await airtableRecordExists(leadgenId);
      if (alreadyExists) {
        return res.status(200).json({ ok: true, duplicate: true });
      }

      // Graph API'den lead detaylarını çek
      const leadResponse = await fetch(
        `https://graph.facebook.com/${leadgenId}?access_token=${process.env.PAGE_TOKEN}`
      );
      const leadData = await leadResponse.json();

      if (!leadResponse.ok) {
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
        return res.status(502).json({
          error: "Failed to write to Airtable",
          details: airtableResult,
        });
      }

      return res.status(200).send("OK");
    } catch (error) {
      console.log(
        "[meta-webhook] POST catch",
        JSON.stringify({ message: error?.message || String(error) })
      );
      return res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}

module.exports = handler;
