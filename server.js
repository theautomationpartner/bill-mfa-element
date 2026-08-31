/**
 * Mini servidor local para probar el BILL MFA Element.
 *
 * Sin dependencias: requiere Node 18+ (usa fetch nativo).
 *
 * Responsabilidades:
 *  1. Guardar las credenciales BILL del lado servidor (nunca en el browser).
 *  2. Generar el sessionId con POST /v3/login y entregarlo al bootloader
 *     (es lo que consume getSessionId() del widget).
 *  3. Recibir el payload del evento `mfaSuccess` y reenviar device +
 *     rememberMeId al Catch Webhook de Zapier.
 */

const http = require('node:http');
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

// Las dos URLs estan publicadas en https://developer.bill.com/docs/elements-overview
//
// No son intercambiables: cada bootloader sirve los widgets desde su propio
// host y el bundle lleva los endpoints cableados. Verificado descargandolos:
//   stage      -> gateway.stage.bill.com, api-stage.bill.com, tank.stage.bill.com
//   produccion -> gateway.prod.bill.com,  api.bill.com,       tank.prod.bill.com
// Un sessionId de produccion contra el widget de stage NUNCA valida.
const BOOTLOADERS = {
  sandbox: 'https://widgets.stage.bdccdn.net/bootloader/index.js',
  production: 'https://apps.bill.com/bootloader/index.js',
};

const GATEWAY = process.env.BILL_GATEWAY_URL || GATEWAYS[ENV] || GATEWAYS.sandbox;
const BOOTLOADER_URL = process.env.BILL_BOOTLOADER_URL || BOOTLOADERS[ENV] || BOOTLOADERS.sandbox;

const DEV_KEY = process.env.BILL_DEV_KEY || '';
const USERNAME = process.env.BILL_USERNAME || '';
const PASSWORD = process.env.BILL_PASSWORD || '';
const ORG_ID = process.env.BILL_ORG_ID || '';
const ZAPIER_WEBHOOK_URL = process.env.ZAPIER_WEBHOOK_URL || '';
const PORT = Number(process.env.PORT || 3000);

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

// Un store por perfil: el rememberMeId de sandbox no sirve en produccion.
const STORE_FILE = DATA_DIR && path.join(DATA_DIR, '.remember-me.' + PROFILE + '.json');

// Bloqueo de seguridad. Cada POST /api/login manda un codigo nuevo al telefono
// del usuario BILL: MAX_ATTEMPTS limita cuantos se pueden pedir sin acertar.
// El contador vive en disco y NO en el browser, para que no se pueda burlar
// borrando localStorage ni abriendo una ventana de incognito.
const MAX_ATTEMPTS = Number(process.env.MAX_MFA_ATTEMPTS || 4);
const ATTEMPTS_FILE = DATA_DIR && path.join(DATA_DIR, '.attempts.' + PROFILE + '.json');

// Espejo en memoria del contador. Es la fuente de verdad dentro del proceso:
// el archivo solo lo hace sobrevivir a un reinicio, cuando hay disco.
let attemptsMemo = null;

// Sesion viva en memoria (nunca se persiste el sessionId a disco).
const state = {
  sessionId: null,
  userId: null,
  orgId: null,
  trusted: false,
};

// ---------------------------------------------------------------------------
// Cliente BILL v3
// ---------------------------------------------------------------------------

async function billFetch(pathname, options) {
  const opts = options || {};
  const headers = { devKey: DEV_KEY };
  if (opts.sessionId) headers.sessionId = opts.sessionId;
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';

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
  return { ok: res.ok, status: res.status, data };
}

/** POST /v3/login: las credenciales que producen el sessionId del widget. */
function billLogin() {
  return billFetch('/v3/login', {
    method: 'POST',
    body: {
      devKey: DEV_KEY,
      username: USERNAME,
      password: PASSWORD,
      organizationId: ORG_ID,
    },
  });
}

/** GET /v3/login/session -> { organizationId, userId, mfaStatus, mfaBypass } */
function billSessionInfo(sessionId) {
  return billFetch('/v3/login/session', { sessionId });
}

// ---------------------------------------------------------------------------
// Handlers de la API local
// ---------------------------------------------------------------------------

const routes = {
  // Nota de seguridad: aqui NO viaja ni BILL_USERNAME ni BILL_PASSWORD.
  // El devKey si, porque el bootloader del widget lo exige en el browser.
  'GET /api/config': async function () {
    const attempts = readAttempts();
    return {
      status: 200,
      body: {
        env: ENV,
        gateway: GATEWAY,
        bootloaderUrl: BOOTLOADER_URL,
        devKey: DEV_KEY,
        zapierConfigured: Boolean(ZAPIER_WEBHOOK_URL),
        credentialsConfigured: Boolean(DEV_KEY && USERNAME && PASSWORD && ORG_ID),
        locked: attempts.failed >= MAX_ATTEMPTS,
        maxAttempts: MAX_ATTEMPTS,
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempts.failed),
      },
    };
  },

  // 1. Genera el sessionId que consume getSessionId() del bootloader.
  'POST /api/login': async function () {
    // Cada login manda un codigo nuevo al telefono: se cuenta antes de nada.
    if (isLocked()) {
      const a = readAttempts();
      log('  BLOQUEADO: ya se agotaron los ' + MAX_ATTEMPTS + ' intentos.');
      return {
        status: 423,
        body: {
          error: 'locked',
          maxAttempts: MAX_ATTEMPTS,
          lockedAt: a.lockedAt,
        },
      };
    }

    const missing = ['BILL_DEV_KEY', 'BILL_USERNAME', 'BILL_PASSWORD', 'BILL_ORG_ID']
      .filter(function (k) { return !process.env[k]; });
    if (missing.length) {
      return { status: 400, body: { error: (ENV_FILE_FOUND ? 'Faltan variables en .env.' + PROFILE + ': ' : 'Faltan variables de entorno: ') + missing.join(', ') } };
    }

    const login = await billLogin();
    if (!login.ok) {
      // La respuesta cruda de BILL se queda en el log del servidor: al browser
      // solo le llega un mensaje generico.
      log('  /v3/login FALLO ' + login.status + ': ' + JSON.stringify(login.data));
      return { status: login.status, body: { error: 'Bill.com rejected the login. Check the server logs.' } };
    }

    state.sessionId = login.data.sessionId;
    state.userId = login.data.userId;
    state.orgId = login.data.organizationId;
    state.trusted = Boolean(login.data.trusted);

    // El login salio bien: a partir de aqui BILL manda el codigo. Este intento
    // se descuenta y solo se perdona si el MFA termina en exito.
    const attempts = countAttempt();

    const info = await billSessionInfo(state.sessionId);

    return {
      status: 200,
      body: {
        sessionId: state.sessionId, // el widget lo necesita en el browser
        userId: state.userId,
        orgId: state.orgId,
        trusted: state.trusted,
        mfaStatus: info.data && info.data.mfaStatus,
        mfaBypass: info.data && info.data.mfaBypass,
        attemptsLeft: Math.max(0, MAX_ATTEMPTS - attempts.failed),
        maxAttempts: MAX_ATTEMPTS,
      },
    };
  },

  // 2. Recibe el payload de mfaSuccess y manda device + rememberMeId a Zapier.
  'POST /api/remember-me': async function (req) {
    const payload = req.body || {};
    log('mfaSuccess recibido. Campos: ' + JSON.stringify(Object.keys(payload)));

    if (!payload.rememberMeId) {
      log('  RECHAZADO: falta rememberMeId.');
      return { status: 400, body: { error: 'Falta rememberMeId en el payload de mfaSuccess.' } };
    }
    if (!payload.deviceId) {
      log('  RECHAZADO: falta deviceId.');
      return {
        status: 400,
        body: {
          error: 'mfaSuccess llego sin deviceId.',
          // VERIFICADO: `device` en POST /v3/login debe ser el `deviceId` que emite
          // el widget, NO un nickname libre. La doc de BILL dice "nickname for your
          // mobile device" y es enganosa: con un nickname arbitrario el login
          // responde trusted:false / mfaStatus:CHALLENGE.
          detalle: 'Sin deviceId, POST /v3/login NO produce una sesion trusted. Repite el MFA marcando "Remember this device".',
        },
      };
    }

    // Exactamente lo que el Zap necesita para el relogin MFA-trusted.
    const record = {
      device: payload.deviceId,
      rememberMeId: payload.rememberMeId,
    };

    writeStore(Object.assign({}, record, {
      userId: state.userId,
      organizationId: state.orgId,
      environment: ENV,
      capturedAt: new Date().toISOString(),
    }));

    // El MFA se completo: se perdonan los intentos gastados.
    resetAttempts();

    let zapier = { sent: false, reason: 'ZAPIER_WEBHOOK_URL no configurado' };
    if (ZAPIER_WEBHOOK_URL) {
      log('  POST -> ' + ZAPIER_WEBHOOK_URL);
      log('  body  -> ' + JSON.stringify(record));
      try {
        const res = await fetch(ZAPIER_WEBHOOK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(record),
        });
        zapier = { sent: res.ok, status: res.status, response: await res.text() };
        log('  Zapier respondio ' + res.status + ': ' + zapier.response);
      } catch (err) {
        zapier = { sent: false, error: String(err) };
        log('  Zapier FALLO: ' + String(err));
      }
    }

    return { status: 200, body: { saved: record, zapier: zapier } };
  },
};

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
    try {
      log(key);
      req.body = await readJsonBody(req);
      const out = await routes[key](req);
      log('  -> ' + out.status);
      return send(res, out.status, out.body);
    } catch (err) {
      // El stack se queda en el log: al browser solo le llega un mensaje
      // generico, para no exponer rutas ni detalles internos del servidor.
      log('  EXCEPCION en ' + key + ': ' + String(err && err.stack ? err.stack : err));
      return send(res, 500, { error: 'Internal server error. Check the server logs.' });
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
  console.log('  BILL MFA Element - app de prueba local');
  console.log('  ---------------------------------------');
  console.log('  URL          http://localhost:' + PORT);
  console.log('  Perfil       ' + PROFILE +
    (ENV_FILE_FOUND ? '  (.env.' + PROFILE + ')' : '  (variables de entorno)'));
  console.log('  Entorno      ' + ENV);
  console.log('  Gateway      ' + GATEWAY);
  console.log('  Bootloader   ' + BOOTLOADER_URL);
  console.log('  Zapier       ' + (ZAPIER_WEBHOOK_URL || '(no configurado)'));
  console.log('  Datos        ' + (DATA_DIR || 'solo memoria (disco de solo lectura)'));
  console.log('  Credenciales ' + (DEV_KEY && USERNAME && PASSWORD && ORG_ID ? 'OK' : 'FALTAN - revisa ' + (ENV_FILE_FOUND ? '.env.' + PROFILE : 'las variables de entorno')));
  console.log('');
});

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

function log(msg) {
  console.log(new Date().toISOString().slice(11, 19) + '  ' + msg);
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body, null, 2));
}

function readJsonBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return Promise.resolve(null);
  return new Promise(function (resolve, reject) {
    let raw = '';
    req.on('data', function (c) {
      raw += c;
      if (raw.length > 1e6) reject(new Error('Body demasiado grande'));
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
function writeStore(record) {
  if (!STORE_FILE) return;
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(record, null, 2), 'utf8');
  } catch (err) {
    log('  aviso: no se pudo guardar el store (' + err.code + '). Se ignora.');
  }
}

// --- Contador de intentos ---------------------------------------------------

function readAttempts() {
  if (attemptsMemo) return attemptsMemo;
  if (ATTEMPTS_FILE) {
    try {
      const data = JSON.parse(fs.readFileSync(ATTEMPTS_FILE, 'utf8'));
      attemptsMemo = { failed: Number(data.failed) || 0, lockedAt: data.lockedAt || null };
      return attemptsMemo;
    } catch (err) {
      /* no existe todavia */
    }
  }
  return { failed: 0, lockedAt: null };
}

function writeAttempts(data) {
  attemptsMemo = data; // el bloqueo vale aunque no haya disco
  if (!ATTEMPTS_FILE) return;
  try {
    fs.writeFileSync(ATTEMPTS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    log('  aviso: contador solo en memoria (' + err.code + ').');
  }
}

function isLocked() {
  return readAttempts().failed >= MAX_ATTEMPTS;
}

/** Un intento mas. Devuelve el estado ya actualizado. */
function countAttempt() {
  const prev = readAttempts();
  const next = {
    failed: prev.failed + 1,
    lockedAt: prev.lockedAt,
  };
  if (next.failed >= MAX_ATTEMPTS && !next.lockedAt) {
    next.lockedAt = new Date().toISOString();
  }
  writeAttempts(next);
  log('  intento ' + next.failed + '/' + MAX_ATTEMPTS +
    (next.failed >= MAX_ATTEMPTS ? ' - BLOQUEADO' : ''));
  return next;
}

/** Exito: se borra el contador y la app vuelve a estar disponible. */
function resetAttempts() {
  attemptsMemo = null;
  if (ATTEMPTS_FILE) {
    try { fs.unlinkSync(ATTEMPTS_FILE); } catch (err) { /* no existia */ }
  }
  log('  contador de intentos reiniciado');
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
