// driveUpload.js
// ─────────────────────────────────────────────────────────────────────────────
//  Upload binário para o Google Drive via OAuth2 + multer.
//  Compatível com Render (sem sistema de arquivos persistente).
//
//  Credenciais lidas de variáveis de ambiente — configure no Render:
//
//    OAUTH2_JSON        conteúdo completo do oauth2.json  (string JSON)
//    TOKEN_JSON         conteúdo completo do token.json   (string JSON)
//    DRIVE_PASTA_MAE_ID ID da pasta-mãe no Drive (opcional; padrão hardcoded)
//
//  Para gerar o TOKEN_JSON pela primeira vez:
//    1. Execute localmente:  node gerarToken.js
//    2. Copie o conteúdo de token.json
//    3. Cole como valor da variável TOKEN_JSON no Render
//
//  O access_token expira, mas o refresh_token renova automaticamente em memória.
//  Ao reiniciar o serviço, o refresh_token original (TOKEN_JSON) é usado de
//  novo — seguro enquanto não for revogado no console do Google.
// ─────────────────────────────────────────────────────────────────────────────

const stream     = require('stream');
const { google } = require('googleapis');

const PASTA_MAE_ID = process.env.DRIVE_PASTA_MAE_ID || '1Ftjgfe8WfTSRZBY2_8qQGm89HpOg-Wp-';

let _drive = null;

function getDrive() {
  if (_drive) return _drive;

  if (!process.env.OAUTH2_JSON) {
    throw new Error('Variável de ambiente OAUTH2_JSON não definida. Configure no Render.');
  }
  if (!process.env.TOKEN_JSON) {
    throw new Error('Variável de ambiente TOKEN_JSON não definida. Configure no Render.');
  }

  let keys, token;
  try { keys  = JSON.parse(process.env.OAUTH2_JSON); }
  catch (e) { throw new Error('OAUTH2_JSON inválido: ' + e.message); }
  try { token = JSON.parse(process.env.TOKEN_JSON);  }
  catch (e) { throw new Error('TOKEN_JSON inválido: '  + e.message); }

  const oAuth2Client = new google.auth.OAuth2(
    keys.installed.client_id,
    keys.installed.client_secret,
    keys.installed.redirect_uris[0]
  );
  oAuth2Client.setCredentials(token);

  // Renova o access_token automaticamente em memória quando expirar.
  oAuth2Client.on('tokens', (newTokens) => {
    console.log('[Drive] Access token renovado (em memória).');
    if (newTokens.refresh_token) {
      // Raramente ocorre; se acontecer, atualize TOKEN_JSON no Render.
      console.warn('[Drive] ATENÇÃO: novo refresh_token recebido. Atualize TOKEN_JSON no Render!');
      console.warn('[Drive] Novo valor:', JSON.stringify({ ...token, ...newTokens }));
    }
  });

  _drive = google.drive({ version: 'v3', auth: oAuth2Client });
  return _drive;
}

// ── Helpers de pasta ─────────────────────────────────────────────────────────

async function getOrCreateFolder(parentId, name) {
  const drive = getDrive();
  const { data } = await drive.files.list({
    q: `'${parentId}' in parents AND name = '${name}' AND mimeType = 'application/vnd.google-apps.folder' AND trashed = false`,
    fields: 'files(id)',
    pageSize: 1,
  });
  if (data.files.length > 0) return data.files[0].id;
  const { data: f } = await drive.files.create({
    requestBody: { name, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] },
    fields: 'id',
  });
  return f.id;
}

function normalizarData(valor) {
  if (!valor) return 'sem-data';
  const s = String(valor).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.substring(0, 10);
  const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
  return s;
}

function mimeParaExt(mime) {
  return ({ 'image/png':'png','image/jpeg':'jpg','image/jpg':'jpg',
            'image/gif':'gif','image/webp':'webp','application/pdf':'pdf' })[mime] || 'bin';
}

// ── API pública ──────────────────────────────────────────────────────────────

async function buscarOuCriarPastaViagem(viagemId) {
  const pastaId = await getOrCreateFolder(PASTA_MAE_ID, `Viagem-${viagemId}`);
  const { data } = await getDrive().files.get({ fileId: pastaId, fields: 'webViewLink' });
  return data.webViewLink;
}

async function uploadArquivo(fileObject, meta) {
  const { viagemId, dataNFs, categoria, slot } = meta;

  const pastaViagemId = await getOrCreateFolder(PASTA_MAE_ID, `Viagem-${viagemId}`);
  const pastaDataId   = await getOrCreateFolder(pastaViagemId, normalizarData(dataNFs));

  const sufixo = slot != null ? `_slot${slot}` : '';
  const cat    = String(categoria || 'arquivo').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 40);
  const ts     = new Date().toTimeString().replace(/:/g, '').substring(0, 6);
  const nome   = `${cat}${sufixo}_${ts}.${mimeParaExt(fileObject.mimetype)}`;

  const bufferStream = new stream.PassThrough();
  bufferStream.end(fileObject.buffer);

  const { data } = await getDrive().files.create({
    media:       { mimeType: fileObject.mimetype, body: bufferStream },
    requestBody: { name: nome, parents: [pastaDataId] },
    fields:      'id, name, webViewLink',
  });

  try {
    await getDrive().permissions.create({
      fileId: data.id,
      requestBody: { role: 'reader', type: 'anyone' },
    });
  } catch (e) {
    console.warn('[Drive] Compartilhamento não aplicado:', e.message);
  }

  console.log(`[Drive] Upload OK: ${data.name} → ${data.webViewLink}`);
  return data.webViewLink;
}

module.exports = { uploadArquivo, buscarOuCriarPastaViagem };
