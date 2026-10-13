/**
 * Captura de un dispositivo MFA-trusted en BILL, 100% del lado servidor.
 *
 * Sin dependencias: requiere Node 18+ (usa fetch nativo).
 *
 * Por que NO se usa el MFA Element (widget) de BILL: el widget exige un
 * fingerprint de ThreatMetrix que corre en un iframe de terceros
 * (#bill-telemetry-iframe). Safari/iOS lo rompe (proteccion contra rastreo,
 * bloqueadores de contenido, pestanas suspendidas mientras el usuario lee el
 * SMS) y el usuario ve "Sorry, something went wrong": el codigo nunca llega a
 * BILL. Aqui el servidor hace las MISMAS llamadas v3 que hace el widget:
 *
 *   POST /v3/login                        -> sessionId (mfaStatus CHALLENGE)
 *   GET  /v3/mfa/phones                   -> ultimos 4 digitos, para la UI
 *   POST /v3/mfa/challenge                -> envia el SMS, devuelve challengeId
 *   POST /v3/mfa/challenge/validate       -> codigo + device -> rememberMeId
 *   POST /v3/login (rememberMeId+device)  -> comprueba trusted + COMPLETE
 *
 * El navegador solo ve un campo para el codigo: ni sessionId, ni devKey, ni
 * iframes, ni fingerprint. Funciona igual en cualquier navegador o sistema.
 */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// ---------------------------------------------------------------------------
// Configuracion
// ---------------------------------------------------------------------------

// Perfil de credenciales: .env.sandbox (por defecto) o .env.live.
//   node server.js            -> sandbox
//   node server.js live       -> produccion
//   BILL_PROFILE=live node server.js
const PROFILE = (process.env.BILL_PROFILE || process.argv[2] || 'sandbox').toLowerCase();

if (PROFILE !== 'sandbox' && PROFILE !== 'live') {
  console.error('Perfil desconocido: "' + PROFILE + '". Usa "sandbox" o "live".');
  process.exit(1);
}

// En local las credenciales salen de .env.<perfil>. En un servidor desplegado
// ese archivo no existe y llegan como variables de entorno reales: por eso el
// archivo es opcional, y loadDotEnv nunca pisa lo que ya venga del entorno.
const ENV_FILE = path.join(__dirname, '.env.' + PROFILE);
const ENV_FILE_FOUND = fs.existsSync(ENV_FILE);
if (ENV_FILE_FOUND) loadDotEnv(ENV_FILE);

const ENV = (process.env.BILL_ENV || (PROFILE === 'live' ? 'production' : 'sandbox')).toLowerCase();

const GATEWAYS = {
  sandbox: 'https://gateway.stage.bill.com/connect',
  production: 'https://gateway.prod.bill.com/connect',
};

const GATEWAY = process.env.BILL_GATEWAY_URL || GATEWAYS[ENV] || GATEWAYS.sandbox;

const DEV_KEY = process.env.BILL_DEV_KEY || '';
const USERNAME = process.env.BILL_USERNAME || '';
const PASSWORD = process.env.BILL_PASSWORD || '';
const ORG_ID = process.env.BILL_ORG_ID || '';
const ZAPIER_WEBHOOK_URL = process.env.ZAPIER_WEBHOOK_URL || '';
const PORT = Number(process.env.PORT || 3000);

// Vigencia real del rememberMeId emitido por /v3/mfa/challenge/validate.
// Verificado: 30 dias (el widget promete 180, pero no es lo que rige).
const REMEMBER_ME_DAYS = Number(process.env.REMEMBER_ME_DAYS || 30);

// --- Modo de prueba ---------------------------------------------------------
// Misma organizacion y mismo devKey: solo cambia el USUARIO de BILL (y con el,
// el telefono que recibe el codigo) y el webhook de Zapier. Se entra abriendo
// la app con ?test=<TEST_MODE_KEY>; sin esa variable el modo no existe.
const TEST_MODE_KEY = process.env.TEST_MODE_KEY || '';

const ACCOUNTS = {
  main: {
    username: USERNAME,
    password: PASSWORD,
    webhook: ZAPIER_WEBHOOK_URL,
    vars: ['BILL_USERNAME', 'BILL_PASSWORD'],
  },
  test: {
    username: process.env.TEST_BILL_USERNAME || '',
    password: process.env.TEST_BILL_PASSWORD || '',
    // Webhook propio a proposito: el rememberMeId de otro usuario no sirve para
    // el login del Zap de los jueves, y si llegara al mismo hook pisaria el bueno.
    webhook: process.env.TEST_ZAPIER_WEBHOOK_URL || '',
    vars: ['TEST_BILL_USERNAME', 'TEST_BILL_PASSWORD'],
  },
};

const TEST_MODE_AVAILABLE = Boolean(TEST_MODE_KEY && ACCOUNTS.test.username && ACCOUNTS.test.password);

// Panel "Test mode trace" tambien en modo normal. Pensado para el despliegue
// de la rama dev (sandbox); en produccion debe quedar sin definir.
const SHOW_TRACE = process.env.SHOW_TRACE === 'true';

// Boton "Send sample to Zapier": manda al Catch Hook del entorno un payload
// con la MISMA estructura que el real (sample: true), sin pasar por BILL, para
// mapear campos en el Zap. Va atado a SHOW_TRACE (solo la variable de entorno,
// no el modo prueba): con el boton visible, cualquiera con la URL podria
// inyectar un ejemplo en el Zap. El endpoint lo exige tambien, no solo la UI.
const SAMPLE_PAYLOAD_ENABLED = SHOW_TRACE;
const SAMPLE_COOLDOWN_MS = 30 * 1000;
const lastSampleAt = { main: 0, test: 0 };

// --- Flujo MFA entre peticiones ---------------------------------------------
// En serverless, "enviar SMS" y "validar codigo" pueden caer en instancias
// distintas: el estado del desafio no puede vivir en memoria. Viaja en el
// browser como un token AES-256-GCM que este no puede leer ni alterar.
// La clave sale de APP_SECRET o, si no existe, de los secretos que ya tiene el
// despliegue (identicos en todas las instancias).
const FLOW_TTL_MS = 15 * 60 * 1000;
const FLOW_KEY = crypto.createHash('sha256')
  .update('bill-mfa-flow|' + (process.env.APP_SECRET ||
    [DEV_KEY, PASSWORD, ACCOUNTS.test.password, TEST_MODE_KEY, ORG_ID].join('|')))
  .digest();

// --- Bitacora del navegador (POST /api/client-log) ---------------------------
const CLIENT_LOG_MAX_BYTES = 64 * 1024;
const CLIENT_LOG_MAX_EVENTS = 50;      // por peticion
const CLIENT_LOG_MAX_PER_MIN = 600;    // por IP y por instancia

// Donde se escriben los archivos de estado. En local es la carpeta del
// proyecto; en un serverless (Vercel, Lambda) esa carpeta es de SOLO LECTURA
// y hay que caer al directorio temporal. Si no se puede escribir en ningun
// lado, la app sigue funcionando solo con memoria.
const DATA_DIR = resolveDataDir();

function resolveDataDir() {
  const candidatos = [process.env.DATA_DIR, __dirname, os.tmpdir()];
  for (const dir of candidatos) {
    if (!dir) continue;
    const probe = path.join(dir, '.write-probe-' + process.pid);
    try {
      fs.writeFileSync(probe, 'ok');
      fs.unlinkSync(probe);
      return dir;
    } catch (err) {
      /* no escribible: probamos el siguiente */
    }
  }
  return null;
}

// Un archivo por perfil y por modo: el rememberMeId de sandbox no sirve en
// produccion, y el del usuario de prueba no sirve para el usuario principal.
//   .remember-me.live.json   .remember-me.live.test.json
function stateFile(prefix, mode) {
  return DATA_DIR && path.join(DATA_DIR, '.' + prefix + '.' + PROFILE + (mode === 'test' ? '.test' : '') + '.json');
}

// Bloqueo de seguridad. Cada SMS enviado (inicio o reenvio) gasta un intento;
// MAX_ATTEMPTS limita cuantos se pueden pedir sin completar el MFA. El
// contador vive en el servidor y NO en el browser, para que no se pueda burlar
// borrando datos del navegador. Cada modo tiene el suyo: las pruebas no pueden
// bloquear al usuario principal.
const MAX_ATTEMPTS = Number(process.env.MAX_MFA_ATTEMPTS || 4);

// Espejo en memoria del contador. Es la fuente de verdad dentro del proceso:
// el archivo solo lo hace sobrevivir a un reinicio, cuando hay disco.
const attemptsMemo = { main: null, test: null };

// ---------------------------------------------------------------------------
// Cliente BILL v3
// ---------------------------------------------------------------------------

async function billFetch(pathname, options) {
  const opts = options || {};
  const headers = { devKey: DEV_KEY };
  if (opts.sessionId) headers.sessionId = opts.sessionId;
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';

  const t0 = Date.now();
  const res = await fetch(GATEWAY + pathname, {
    method: opts.method || 'GET',
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    data = { raw: text };
  }
  const out = { ok: res.ok, status: res.status, data, code: billErrorCode(data), ms: Date.now() - t0 };
  // Una linea por llamada: es la traza que sustituye a la del widget.
  log('  BILL ' + (opts.method || 'GET') + ' ' + pathname + ' -> ' + res.status +
    (out.code ? ' ' + out.code : '') + ' (' + out.ms + ' ms)');
  if (!res.ok) log('    ' + clip(JSON.stringify(data), 600));
  return out;
}

/** BILL v3 responde los errores como [{ code: "BDC_1357", message: ... }]. */
function billErrorCode(data) {
  return Array.isArray(data) && data[0] && data[0].code ? data[0].code : null;
}

/**
 * POST /v3/login. Con `trust` ({ rememberMeId, device }) es exactamente el
 * login que hace el Zap de los jueves: debe nacer trusted / COMPLETE.
 */
function billLogin(account, trust) {
  const body = {
    devKey: DEV_KEY,
    username: account.username,
    password: account.password,
    organizationId: ORG_ID,
  };
  if (trust) {
    body.rememberMeId = trust.rememberMeId;
    body.device = trust.device;
  }
  return billFetch('/v3/login', { method: 'POST', body });
}

/** GET /v3/login/session -> { organizationId, userId, mfaStatus, mfaBypass } */
function billSessionInfo(sessionId) {
  return billFetch('/v3/login/session', { sessionId });
}

/** POST /v3/mfa/challenge: BILL manda el SMS al telefono primario. */
function billSendChallenge(sessionId) {
  return billFetch('/v3/mfa/challenge', { method: 'POST', sessionId, body: { useBackup: false } });
}

/** Cierre de sesiones auxiliares. Nunca debe romper el flujo. */
async function billLogout(sessionId) {
  if (!sessionId) return;
  try {
    await billFetch('/v3/logout', { method: 'POST', sessionId, body: {} });
  } catch (err) {
    log('  aviso: logout fallo (' + String(err) + '). Se ignora.');
  }
}

// ---------------------------------------------------------------------------
// Handlers de la API local
// ---------------------------------------------------------------------------

const routes = {
  // Nota de seguridad: aqui no viaja ninguna credencial. Ni siquiera el devKey:
  // sin widget, el browser ya no lo necesita.
  'GET /api/config': async function (req) {
    const mode = req.mode;
    const account = ACCOUNTS[mode];
    const attempts = readAttempts(mode);
    return {
      status: 200,
      body: {
        env: ENV,
        mode: mode,
        // Solo en modo prueba, y enmascarado: para que quien prueba vea a que
        // usuario (y telefono) va el codigo.
        testUser: mode === 'test' ? maskEmail(account.username) : undefined,
        showTrace: mode === 'test' || SHOW_TRACE,
        samplePayload: SAMPLE_PAYLOAD_ENABLED && Boolean(account.webhook),
        zapierConfigured: Boolean(account.webhook),
        credentialsConfigured: Boolean(DEV_KEY && account.username && account.password && ORG_ID),
        locked: attempts.failed >= MAX_ATTEMPTS,
        maxAttempts: MAX_ATTEMPTS,
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempts.failed),
        rememberDays: REMEMBER_ME_DAYS,
      },
    };
  },

  // 1. Login + desafio: BILL manda el SMS. Devuelve el token del flujo.
  'POST /api/mfa/start': async function (req) {
    const mode = req.mode;
    const account = ACCOUNTS[mode];

    if (isLocked(mode)) return lockedResponse(mode);

    const missing = ['BILL_DEV_KEY', 'BILL_ORG_ID'].concat(account.vars)
      .filter(function (k) { return !process.env[k]; });
    if (missing.length) {
      return { status: 400, body: { error: 'not_configured', detail: missing.join(', ') } };
    }

    const login = await billLogin(account);
    if (!login.ok) {
      // El detalle de BILL se queda en el log: al browser solo el codigo.
      return { status: 502, body: { error: 'login_rejected', billCode: login.code } };
    }
    const sessionId = login.data.sessionId;

    const info = await billSessionInfo(sessionId);
    const mfaStatus = info.data && info.data.mfaStatus;
    log('  mfaStatus=' + mfaStatus + ' mfaBypass=' + (info.data && info.data.mfaBypass));

    if (mfaStatus !== 'CHALLENGE') {
      await billLogout(sessionId);
      // SETUP: el usuario no tiene telefono MFA registrado; se hace una vez en
      // la web de BILL. DISABLED / COMPLETE: no hay desafio que resolver.
      return {
        status: 409,
        body: { error: mfaStatus === 'SETUP' ? 'mfa_setup_required' : 'unexpected_mfa_status', mfaStatus: mfaStatus },
      };
    }

    const phones = await billFetch('/v3/mfa/phones', { sessionId });
    const list = (phones.data && phones.data.results) || [];
    const phone = list.find(function (p) { return p.primary; }) || list[0] || {};

    const challenge = await billSendChallenge(sessionId);
    if (!challenge.ok || !challenge.data || !challenge.data.challengeId) {
      await billLogout(sessionId);
      return challengeErrorResponse(challenge);
    }

    // El SMS salio: recien ahora se gasta un intento.
    const attempts = countAttempt(mode);

    // El `device` que el widget sacaba de ThreatMetrix lo genera el servidor.
    // Mismo formato (32 alfanumericos); BILL lo empareja con el rememberMeId.
    const flow = sealFlow({
      mode: mode,
      sessionId: sessionId,
      challengeId: challenge.data.challengeId,
      device: newDeviceId(),
      last4: phone.last4digits || null,
      iat: Date.now(),
    });

    return {
      status: 200,
      body: {
        flow: flow,
        last4: phone.last4digits || null,
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempts.failed),
        maxAttempts: MAX_ATTEMPTS,
      },
    };
  },

  // 2. Reenvio del SMS con la misma sesion. Tambien gasta un intento.
  'POST /api/mfa/resend': async function (req) {
    const mode = req.mode;
    const flow = openFlow((req.body || {}).flow, mode);
    if (!flow) return { status: 410, body: { error: 'flow_expired' } };
    if (isLocked(mode)) return lockedResponse(mode);

    const challenge = await billSendChallenge(flow.sessionId);
    if (!challenge.ok || !challenge.data || !challenge.data.challengeId) {
      return challengeErrorResponse(challenge);
    }
    const attempts = countAttempt(mode);

    return {
      status: 200,
      body: {
        flow: sealFlow(Object.assign({}, flow, { challengeId: challenge.data.challengeId, iat: Date.now() })),
        last4: flow.last4,
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempts.failed),
        maxAttempts: MAX_ATTEMPTS,
      },
    };
  },

  // 3. Valida el codigo, comprueba que el par abre una sesion trusted y lo
  //    manda a Zapier. Solo se envia a Zapier un par VERIFICADO.
  'POST /api/mfa/verify': async function (req) {
    const mode = req.mode;
    const account = ACCOUNTS[mode];
    const body = req.body || {};
    const code = String(body.code || '').trim();

    if (!/^\d{6}$/.test(code)) return { status: 400, body: { error: 'invalid_code_format' } };
    const flow = openFlow(body.flow, mode);
    if (!flow) return { status: 410, body: { error: 'flow_expired' } };

    const validate = await billFetch('/v3/mfa/challenge/validate', {
      method: 'POST',
      sessionId: flow.sessionId,
      body: { challengeId: flow.challengeId, token: code, rememberMe: true, device: flow.device },
    });

    if (!validate.ok) {
      const map = {
        BDC_1357: { status: 400, error: 'incorrect_code' },
        BDC_1356: { status: 400, error: 'code_expired' },
        BDC_1358: { status: 429, error: 'too_many_code_attempts' },
      };
      const known = map[validate.code];
      if (known) return { status: known.status, body: { error: known.error } };
      if (validate.status === 401) return { status: 410, body: { error: 'session_expired', billCode: validate.code } };
      return { status: 502, body: { error: 'bill_error', billCode: validate.code } };
    }

    const rememberMeId = validate.data && validate.data.rememberMeId;
    if (!rememberMeId) {
      log('  validate OK pero sin rememberMeId: ' + clip(JSON.stringify(validate.data), 300));
      return { status: 502, body: { error: 'no_remember_me_id' } };
    }
    // La sesion del desafio ya no hace falta.
    await billLogout(flow.sessionId);

    // Prueba de fuego: el mismo login que hara el Zap.
    const check = await billLogin(account, { rememberMeId: rememberMeId, device: flow.device });
    let trusted = false;
    let mfaStatus = null;
    if (check.ok) {
      trusted = Boolean(check.data.trusted);
      const info = await billSessionInfo(check.data.sessionId);
      mfaStatus = info.data && info.data.mfaStatus;
      await billLogout(check.data.sessionId);
    }
    log('  verificacion del par: trusted=' + trusted + ' mfaStatus=' + mfaStatus);

    const capturedAt = new Date();

    if (!(trusted && mfaStatus === 'COMPLETE')) {
      writeStore(mode, {
        device: flow.device, rememberMeId: rememberMeId, environment: ENV,
        capturedAt: capturedAt.toISOString(), verified: false, trusted: trusted, mfaStatus: mfaStatus,
      });
      return {
        status: 502,
        body: { error: 'not_trusted', trusted: trusted, mfaStatus: mfaStatus, loginStatus: check.status, billCode: check.code },
      };
    }

    const record = buildZapierRecord(mode, account, {
      device: flow.device,
      rememberMeId: rememberMeId,
      capturedAt: capturedAt,
      sample: false,
    });

    writeStore(mode, Object.assign({}, record, { environment: ENV, verified: true }));

    // MFA completado: se perdonan los intentos gastados.
    resetAttempts(mode);

    const zapier = await sendToZapier(mode, account.webhook, record);
    return {
      status: 200,
      body: { trusted: true, expiresAt: record.expiresAt, rememberDays: REMEMBER_ME_DAYS, zapier: zapier },
    };
  },

  // 4. Payload de ejemplo al Catch Hook del entorno, sin pasar por BILL. Misma
  //    estructura que el real (buildZapierRecord), con sample: true y valores
  //    que no sirven para loguearse: el Zap debe filtrar sample == false.
  'POST /api/zapier/sample': async function (req) {
    const mode = req.mode;
    const account = ACCOUNTS[mode];
    if (!SAMPLE_PAYLOAD_ENABLED) return { status: 404, body: { error: 'sample_disabled' } };
    if (!account.webhook) return { status: 409, body: { error: 'zapier_not_configured' } };

    const wait = lastSampleAt[mode] + SAMPLE_COOLDOWN_MS - Date.now();
    if (wait > 0) return { status: 429, body: { error: 'sample_cooldown', retryInSeconds: Math.ceil(wait / 1000) } };
    lastSampleAt[mode] = Date.now();

    const record = buildZapierRecord(mode, account, {
      device: 'SAMPLE' + newDeviceId().slice(6),
      rememberMeId: '!SAMPLE-not-a-real-rememberMeId-' + crypto.randomBytes(12).toString('hex'),
      capturedAt: new Date(),
      sample: true,
    });
    const zapier = await sendToZapier(mode, account.webhook, record);
    // El ejemplo no tiene secretos: se devuelve para verlo en pantalla.
    return { status: zapier.sent ? 200 : 502, body: { zapier: zapier, payload: record } };
  },

  // 5. Bitacora del navegador -> logs de Vercel. Una linea JSON por evento,
  //    filtrable por traceId. El front ya redacta secretos antes de mandar.
  'POST /api/client-log': async function (req) {
    const b = req.body || {};
    const events = Array.isArray(b.events) ? b.events.slice(0, CLIENT_LOG_MAX_EVENTS) : [];
    const ip = clientIp(req);
    if (!allowClientLog(ip, events.length)) {
      return { status: 429, body: { error: 'Too many log events.' } };
    }

    const ctx = {
      src: 'client',
      traceId: clip(b.traceId, 64),
      mode: b.mode === 'test' ? 'test' : 'main',
      env: ENV,
      ua: clip(b.ua, 300),
      ip: ip,
    };
    for (const ev of events) {
      if (!ev || typeof ev !== 'object') continue;
      const level = ev.level === 'error' || ev.level === 'warn' ? ev.level : 'info';
      const line = clip(JSON.stringify(Object.assign({}, ctx, {
        at: clip(ev.at, 40),
        ms: Number(ev.ms) || 0,
        step: clip(ev.step, 80),
        level: level,
        data: ev.data,
      })), 4000);
      // stderr = nivel error en Vercel: se puede filtrar solo los fallos.
      if (level === 'error') console.error(line);
      else console.log(line);
    }
    return { status: 204, body: null };
  },
};

function lockedResponse(mode) {
  const a = readAttempts(mode);
  log('  BLOQUEADO: ya se agotaron los ' + MAX_ATTEMPTS + ' intentos [' + mode + '].');
  return { status: 423, body: { error: 'locked', maxAttempts: MAX_ATTEMPTS, lockedAt: a.lockedAt } };
}

function challengeErrorResponse(challenge) {
  if (challenge.code === 'BDC_1410') return { status: 429, body: { error: 'sms_limit_reached' } };
  if (challenge.code === 'BDC_1354') return { status: 409, body: { error: 'phone_invalid' } };
  if (challenge.status === 401) return { status: 410, body: { error: 'session_expired' } };
  return { status: 502, body: { error: 'challenge_failed', billCode: challenge.code } };
}

/**
 * El payload que recibe el Catch Hook. Unica fuente de la estructura: la usan
 * el envio real y el de ejemplo, asi lo mapeado en el Zap siempre coincide.
 */
function buildZapierRecord(mode, account, f) {
  const record = {
    device: f.device,
    rememberMeId: f.rememberMeId,
    capturedAt: f.capturedAt.toISOString(),
    expiresAt: new Date(f.capturedAt.getTime() + REMEMBER_ME_DAYS * 86400000).toISOString(),
    environment: ENV,
    // true = payload de ejemplo del boton; el Zap debe filtrar sample == false.
    sample: f.sample,
  };
  // En modo prueba el Zap tiene que poder distinguir de quien es el par.
  if (mode === 'test') {
    record.mode = 'test';
    record.username = account.username;
  }
  return record;
}

async function sendToZapier(mode, webhook, record) {
  if (!webhook) {
    return { sent: false, reason: (mode === 'test' ? 'TEST_' : '') + 'ZAPIER_WEBHOOK_URL no configurado' };
  }
  log('  POST -> Zapier [' + mode + ']');
  try {
    const res = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record),
    });
    const text = await res.text();
    log('  Zapier respondio ' + res.status + ': ' + clip(text, 200));
    return { sent: res.ok, status: res.status };
  } catch (err) {
    log('  Zapier FALLO: ' + String(err));
    return { sent: false, error: String(err) };
  }
}

// ---------------------------------------------------------------------------
// Servidor HTTP
// ---------------------------------------------------------------------------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
};

const server = http.createServer(async function (req, res) {
  const url = new URL(req.url, 'http://localhost:' + PORT);
  const key = req.method + ' ' + url.pathname;

  if (routes[key]) {
    // traceId: lo genera el browser por carga de pagina y lo manda en cada
    // llamada, para unir en Vercel las lineas del servidor con las del cliente.
    req.traceId = clip(String(req.headers['x-trace-id'] || '').replace(/[^\w-]/g, ''), 64);
    req.mode = resolveMode(req);
    if (!req.mode) {
      log(key + ' -> 403 (clave de prueba invalida)');
      return send(res, 403, { error: 'invalid_test_link' });
    }
    // La bitacora ya escribe sus propias lineas: no se duplica el ruido.
    const quiet = key === 'POST /api/client-log';
    try {
      if (!quiet) log(key + ' [' + req.mode + (req.traceId ? ' trace=' + req.traceId : '') + ']');
      req.body = await readJsonBody(req, quiet ? CLIENT_LOG_MAX_BYTES : 1e6);
      const out = await routes[key](req);
      if (!quiet) log('  -> ' + out.status + (out.body && out.body.error ? ' ' + out.body.error : ''));
      return send(res, out.status, out.body);
    } catch (err) {
      // El stack se queda en el log: al browser solo le llega un mensaje
      // generico, para no exponer rutas ni detalles internos del servidor.
      log('  EXCEPCION en ' + key + ': ' + String(err && err.stack ? err.stack : err));
      return send(res, 500, { error: 'internal_error' });
    }
  }

  // Estaticos
  const publicDir = path.join(__dirname, 'public');
  const file = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\/+/, '');
  const full = path.join(publicDir, file);
  if (full.indexOf(publicDir) !== 0 || !fs.existsSync(full)) {
    return send(res, 404, { error: 'Not found' });
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
  fs.createReadStream(full).pipe(res);
});

server.listen(PORT, function () {
  console.log('');
  console.log('  BILL MFA - captura de dispositivo trusted (sin widget)');
  console.log('  ------------------------------------------------------');
  console.log('  URL          http://localhost:' + PORT);
  console.log('  Perfil       ' + PROFILE +
    (ENV_FILE_FOUND ? '  (.env.' + PROFILE + ')' : '  (variables de entorno)'));
  console.log('  Entorno      ' + ENV);
  console.log('  Gateway      ' + GATEWAY);
  console.log('  Zapier       ' + (ZAPIER_WEBHOOK_URL ? 'configurado' : '(no configurado)'));
  console.log('  Modo prueba  ' + (TEST_MODE_AVAILABLE
    ? 'activo (' + maskEmail(ACCOUNTS.test.username) + ', webhook ' +
      (ACCOUNTS.test.webhook ? 'OK' : 'NO configurado') + ')'
    : 'inactivo (faltan TEST_MODE_KEY / TEST_BILL_USERNAME / TEST_BILL_PASSWORD)'));
  console.log('  Vigencia     rememberMeId ' + REMEMBER_ME_DAYS + ' dias');
  console.log('  Datos        ' + (DATA_DIR || 'solo memoria (disco de solo lectura)'));
  console.log('  Credenciales ' + (DEV_KEY && USERNAME && PASSWORD && ORG_ID ? 'OK' : 'FALTAN (usuario principal) - revisa ' + (ENV_FILE_FOUND ? '.env.' + PROFILE : 'las variables de entorno')));
  console.log('');
});

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

function log(msg) {
  console.log(new Date().toISOString().slice(11, 19) + '  ' + msg);
}

function send(res, status, body) {
  if (body === null) {
    res.writeHead(status);
    return res.end();
  }
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body, null, 2));
}

function readJsonBody(req, maxBytes) {
  if (req.method === 'GET' || req.method === 'HEAD') return Promise.resolve(null);
  return new Promise(function (resolve, reject) {
    let raw = '';
    req.on('data', function (c) {
      raw += c;
      if (raw.length > maxBytes) reject(new Error('Body demasiado grande'));
    });
    req.on('end', function () {
      if (!raw) return resolve(null);
      try { resolve(JSON.parse(raw)); } catch (err) { resolve({ raw: raw }); }
    });
    req.on('error', reject);
  });
}

// El store es una comodidad para depurar: el dato que importa es el que se
// manda a Zapier. Nunca debe romper la peticion si el disco no acepta escrituras.
function writeStore(mode, record) {
  const file = stateFile('remember-me', mode);
  if (!file) return;
  try {
    fs.writeFileSync(file, JSON.stringify(record, null, 2), 'utf8');
  } catch (err) {
    log('  aviso: no se pudo guardar el store (' + err.code + '). Se ignora.');
  }
}

// --- Token del flujo MFA ----------------------------------------------------

function sealFlow(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', FLOW_KEY, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64url');
}

/** null si el token es invalido, de otro modo, o vencido. */
function openFlow(token, mode) {
  if (typeof token !== 'string' || token.length > 4000) return null;
  try {
    const buf = Buffer.from(token, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', FLOW_KEY, buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    const data = JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8'));
    if (data.mode !== mode || Date.now() - data.iat > FLOW_TTL_MS) return null;
    return data;
  } catch (err) {
    return null;
  }
}

/** 32 alfanumericos, el mismo formato que el deviceId que emitia el widget. */
function newDeviceId() {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (const b of crypto.randomBytes(32)) s += abc[b % abc.length];
  return s;
}

// --- Modo y bitacora --------------------------------------------------------

/**
 * 'main' sin cabecera X-Test-Key, 'test' con la clave correcta, null con una
 * clave incorrecta: un enlace de prueba mal copiado NO debe caer al usuario
 * principal y mandarle un codigo a su telefono.
 */
function resolveMode(req) {
  const key = req.headers['x-test-key'];
  if (!key) return 'main';
  if (!TEST_MODE_AVAILABLE) return null;
  const a = Buffer.from(String(key));
  const b = Buffer.from(TEST_MODE_KEY);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? 'test' : null;
}

function maskEmail(email) {
  const s = String(email || '');
  const at = s.indexOf('@');
  if (at < 1) return s ? s.slice(0, 2) + '***' : '';
  return s.slice(0, Math.min(2, at)) + '***' + s.slice(at);
}

function clip(value, max) {
  if (value === undefined || value === null) return undefined;
  const s = String(value);
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || (req.socket && req.socket.remoteAddress) || 'unknown';
}

// La bitacora es publica: un tope por IP evita que alguien inunde los logs.
// Vive en memoria, asi que es por instancia; alcanza para cortar el abuso.
const clientLogBudget = new Map();

function allowClientLog(ip, count) {
  const now = Date.now();
  if (clientLogBudget.size > 5000) clientLogBudget.clear();
  let b = clientLogBudget.get(ip);
  if (!b || now - b.windowStart > 60000) {
    b = { windowStart: now, count: 0 };
    clientLogBudget.set(ip, b);
  }
  b.count += count;
  return b.count <= CLIENT_LOG_MAX_PER_MIN;
}

// --- Contador de intentos ---------------------------------------------------

function readAttempts(mode) {
  if (attemptsMemo[mode]) return attemptsMemo[mode];
  const file = stateFile('attempts', mode);
  if (file) {
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      attemptsMemo[mode] = { failed: Number(data.failed) || 0, lockedAt: data.lockedAt || null };
      return attemptsMemo[mode];
    } catch (err) {
      /* no existe todavia */
    }
  }
  return { failed: 0, lockedAt: null };
}

function writeAttempts(mode, data) {
  attemptsMemo[mode] = data; // el bloqueo vale aunque no haya disco
  const file = stateFile('attempts', mode);
  if (!file) return;
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    log('  aviso: contador solo en memoria (' + err.code + ').');
  }
}

function isLocked(mode) {
  return readAttempts(mode).failed >= MAX_ATTEMPTS;
}

/** Un intento mas. Devuelve el estado ya actualizado. */
function countAttempt(mode) {
  const prev = readAttempts(mode);
  const next = {
    failed: prev.failed + 1,
    lockedAt: prev.lockedAt,
  };
  if (next.failed >= MAX_ATTEMPTS && !next.lockedAt) {
    next.lockedAt = new Date().toISOString();
  }
  writeAttempts(mode, next);
  log('  SMS ' + next.failed + '/' + MAX_ATTEMPTS + ' [' + mode + ']' +
    (next.failed >= MAX_ATTEMPTS ? ' - BLOQUEADO' : ''));
  return next;
}

/** Exito: se borra el contador y la app vuelve a estar disponible. */
function resetAttempts(mode) {
  attemptsMemo[mode] = null;
  const file = stateFile('attempts', mode);
  if (file) {
    try { fs.unlinkSync(file); } catch (err) { /* no existia */ }
  }
  log('  contador de intentos reiniciado [' + mode + ']');
}

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m || line.trim().indexOf('#') === 0) continue;
    const value = m[2].replace(/^["']|["']$/g, '');
    if (process.env[m[1]] === undefined) process.env[m[1]] = value;
  }
}
