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

/** İlk leadgen değişikliğini bul (tek POST'ta birden fazla changes olabilir). */
function extractLeadgenFromPayload(payload) {
  for (const ent of payload?.entry || []) {
    for (const ch of ent?.changes || []) {
      const v = ch?.value;
      if (v != null && v.leadgen_id != null && String(v.leadgen_id).length > 0) {
        return { leadgenId: String(v.leadgen_id), webhookValue: v };
      }
    }
  }
  return { leadgenId: null, webhookValue: null };
}

function graphApiVersion() {
  const raw = String(process.env.GRAPH_API_VERSION || "v21.0").trim();
  return raw.startsWith("v") ? raw : `v${raw}`;
}

/** Airtable tablosu (Leads-Grid view.csv) ile aynı alan adları. */
const AT = {
  leadgenId: "Leadgen ID",
  fullName: "Full Name",
  email: "Email",
  phone: "Phone",
  formId: "Form ID",
  pageId: "Page ID",
  adId: "Ad ID",
  createdTimeMeta: "Created Time (Meta)",
  rawPayload: "Raw Payload",
  source: "Source",
  syncStatus: "Sync Status",
  errorMessage: "Error Message",
  receivedAt: "Received At",
};

function rawPayloadFieldName() {
  return String(process.env.AIRTABLE_RAW_PAYLOAD_FIELD || AT.rawPayload).trim() || AT.rawPayload;
}

function leadSourceLabel() {
  return String(process.env.LEAD_SOURCE_LABEL || "Meta Lead Ads Webhook").trim();
}

/** Single select seçenekleri tablodaki etiketlerle birebir eşleşmeli. */
function syncStatusValueSynced() {
  return String(process.env.AIRTABLE_SYNC_STATUS_SYNCED || "Synced").trim();
}

function syncStatusValuePartial() {
  return String(process.env.AIRTABLE_SYNC_STATUS_PARTIAL || "Partial").trim();
}

function truthyEnv(name) {
  const v = String(process.env[name] ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/** Received At çoğu tabloda formül veya otomatik alan → 422. Yazmak için AIRTABLE_WRITE_RECEIVED_AT=true */
function shouldWriteReceivedAt() {
  return truthyEnv("AIRTABLE_WRITE_RECEIVED_AT");
}

function shouldWriteSyncStatus() {
  const v = String(process.env.AIRTABLE_WRITE_SYNC_STATUS ?? "").trim().toLowerCase();
  if (v === "0" || v === "false" || v === "no") return false;
  return true;
}

/** Graph başarısızken Sync Status yazmak çoğu tabloda 422 (seçenek yok). Açmak için =true */
function shouldWriteSyncStatusOnGraphFailure() {
  return truthyEnv("AIRTABLE_WRITE_SYNC_STATUS_ON_FAILURE");
}

/** Graph hata metni; alan formül/single-line uyumsuzsa 422. Açmak için =true */
function shouldWriteErrorMessageOnGraphFailure() {
  return truthyEnv("AIRTABLE_WRITE_ERROR_MESSAGE_ON_FAILURE");
}

function shouldWriteSource() {
  const v = String(process.env.AIRTABLE_WRITE_SOURCE ?? "").trim().toLowerCase();
  if (v === "0" || v === "false" || v === "no") return false;
  return true;
}

function jsonPreview(obj, maxLen) {
  try {
    const s = JSON.stringify(obj);
    return s.length > maxLen ? `${s.slice(0, maxLen)}…` : s;
  } catch {
    return String(obj).slice(0, maxLen);
  }
}

/** Boş / null alanları POST gövdesinden çıkar (Airtable tip hatalarını azaltır). */
function omitEmptyFields(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "string" && v.trim() === "") continue;
    out[k] = v;
  }
  return out;
}

/** Webhook `value` içindeki ID / zaman alanları → CSV sütunları. */
function idFieldsFromWebhookValue(v) {
  if (!v || typeof v !== "object") return {};
  const out = {};
  if (v.form_id != null && String(v.form_id).length > 0) {
    out[AT.formId] = String(v.form_id);
  }
  if (v.page_id != null && String(v.page_id).length > 0) {
    out[AT.pageId] = String(v.page_id);
  }
  if (v.ad_id != null && String(v.ad_id).length > 0) {
    out[AT.adId] = String(v.ad_id);
  }
  if (v.created_time != null) {
    const sec = Number(v.created_time);
    if (!Number.isNaN(sec) && sec > 0) {
      out[AT.createdTimeMeta] = new Date(sec * 1000).toISOString();
    }
  }
  return out;
}

/** Graph lead cevabından CSV sütunları (created_time genelde ISO string). */
function idFieldsFromGraphLead(leadData) {
  if (!leadData || typeof leadData !== "object") return {};
  const out = {};
  if (leadData.form_id != null && String(leadData.form_id).length > 0) {
    out[AT.formId] = String(leadData.form_id);
  }
  if (leadData.page_id != null && String(leadData.page_id).length > 0) {
    out[AT.pageId] = String(leadData.page_id);
  }
  if (leadData.ad_id != null && String(leadData.ad_id).length > 0) {
    out[AT.adId] = String(leadData.ad_id);
  }
  if (leadData.created_time) {
    out[AT.createdTimeMeta] = String(leadData.created_time);
  }
  return out;
}

function buildRawPayloadJson(webhookValue, graphStatus, leadData, graphOk) {
  const maxLen = 95000;
  const payload = {
    webhook_value: webhookValue || null,
    graph_ok: graphOk,
    graph_http_status: graphStatus ?? null,
    graph_body: graphOk ? leadData : leadData?.error ?? leadData ?? null,
  };
  const s = JSON.stringify(payload);
  return s.length > maxLen ? `${s.slice(0, maxLen)}…` : s;
}

function graphErrorMessage(leadData) {
  const e = leadData?.error;
  if (!e) return JSON.stringify(leadData ?? {}).slice(0, 8000);
  const parts = [e.message, e.type && `type=${e.type}`, e.code != null && `code=${e.code}`].filter(Boolean);
  return parts.join(" | ").slice(0, 10000);
}

async function airtableRecordExists(leadgenId) {
  const formula = encodeURIComponent(`{${AT.leadgenId}}='${leadgenId}'`);
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

async function airtableCreateLeadRecord(fields) {
  const airtableResponse = await fetch(
    `https://api.airtable.com/v0/${process.env.BASE_ID}/Leads`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.AIRTABLE_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ fields }),
    }
  );
  const airtableResult = await airtableResponse.json();
  return { airtableResponse, airtableResult };
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
      const { leadgenId, webhookValue } = extractLeadgenFromPayload(payload);
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
        return res.status(200).send("OK");
      }

      // Graph API: sürüm + fields (sürümsüz URL bazı ortamlarda 400/deprecated verebilir).
      const gv = graphApiVersion();
      const graphQs = new URLSearchParams({
        access_token: String(process.env.PAGE_TOKEN || ""),
        fields:
          "field_data,created_time,id,ad_id,form_id,page_id,adset_id,campaign_id",
      });
      const leadResponse = await fetch(
        `https://graph.facebook.com/${gv}/${encodeURIComponent(leadgenId)}?${graphQs.toString()}`
      );
      const leadData = await leadResponse.json();

      const rawField = rawPayloadFieldName();
      let airtableFields;

      if (leadResponse.ok) {
        const fieldData = leadData.field_data || [];
        const getFieldValue = (name) =>
          fieldData.find((f) => f.name === name)?.values?.[0] || null;
        airtableFields = omitEmptyFields({
          [AT.leadgenId]: leadgenId,
          [AT.fullName]: getFieldValue("full_name"),
          [AT.email]: getFieldValue("email"),
          [AT.phone]: getFieldValue("phone_number"),
          ...idFieldsFromGraphLead(leadData),
          [rawField]: buildRawPayloadJson(
            webhookValue,
            leadResponse.status,
            leadData,
            true
          ),
          ...(shouldWriteSource() ? { [AT.source]: leadSourceLabel() } : {}),
          ...(shouldWriteSyncStatus()
            ? { [AT.syncStatus]: syncStatusValueSynced() }
            : {}),
          ...(shouldWriteReceivedAt()
            ? { [AT.receivedAt]: new Date().toISOString() }
            : {}),
        });
      } else {
        const ge = leadData?.error;
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_graph_api_error",
          reqId,
          graphStatus: leadResponse.status,
          graphErrorCode: ge?.code,
          graphErrorType: ge?.type,
          graphErrorMessage: ge?.message,
          graphErrorSubcode: ge?.error_subcode,
          graphFbtraceId: ge?.fbtrace_id,
          graphErrorUserMsg: ge?.error_user_msg,
          graphErrorUserTitle: ge?.error_user_title,
          graphErrorFull: jsonPreview(leadData, 4000),
          pageTokenConfigured: Boolean(String(process.env.PAGE_TOKEN || "").trim()),
          pageTokenLength: String(process.env.PAGE_TOKEN || "").length,
          graphHint190:
            ge?.code === 190
              ? "OAuth 190: PAGE_TOKEN invalid/expired/wrong app. Regenerate long-lived Page token (leads_retrieval, pages_read_engagement, …) and set Vercel PAGE_TOKEN."
              : undefined,
          ms: Date.now() - t0,
        });
        // AIRTABLE_PARTIAL_MINIMAL=true → sadece Leadgen ID + Raw Payload (422 debug / tek seçenek)
        if (truthyEnv("AIRTABLE_PARTIAL_MINIMAL")) {
          airtableFields = omitEmptyFields({
            [AT.leadgenId]: leadgenId,
            [rawField]: buildRawPayloadJson(
              webhookValue,
              leadResponse.status,
              leadData,
              false
            ),
          });
        } else {
          airtableFields = omitEmptyFields({
            [AT.leadgenId]: leadgenId,
            ...idFieldsFromWebhookValue(webhookValue),
            [rawField]: buildRawPayloadJson(
              webhookValue,
              leadResponse.status,
              leadData,
              false
            ),
            ...(shouldWriteSource() ? { [AT.source]: leadSourceLabel() } : {}),
            ...(shouldWriteSyncStatusOnGraphFailure()
              ? { [AT.syncStatus]: syncStatusValuePartial() }
              : {}),
            ...(shouldWriteErrorMessageOnGraphFailure()
              ? { [AT.errorMessage]: graphErrorMessage(leadData) }
              : {}),
            ...(shouldWriteReceivedAt()
              ? { [AT.receivedAt]: new Date().toISOString() }
              : {}),
          });
        }
      }

      const { airtableResponse, airtableResult } =
        await airtableCreateLeadRecord(airtableFields);

      if (!airtableResponse.ok) {
        emitRequestLog({
          svc: "meta-webhook",
          event: "post_airtable_write_error",
          reqId,
          airtableStatus: airtableResponse.status,
          airtableErrorType: airtableResult?.error?.type,
          airtableErrorMessage: airtableResult?.error?.message,
          airtableFieldErrors: airtableResult?.error?.errors,
          airtableBodyPreview: jsonPreview(airtableResult, 12000),
          airtableFieldKeysSent: Object.keys(airtableFields),
          ms: Date.now() - t0,
        });
        return res.status(502).json({
          error: "Failed to write to Airtable",
          details: airtableResult,
        });
      }

      emitRequestLog({
        svc: "meta-webhook",
        event: leadResponse.ok ? "post_success_200" : "post_success_partial_graph",
        reqId,
        graphOk: leadResponse.ok,
        ms: Date.now() - t0,
      });
      // Meta webhook: 2xx yeterli; gövde düz metin kalsın.
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
