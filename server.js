if (process.env.NODE_ENV !== 'production') require('dotenv').config();
const express  = require('express');
const path     = require('path');
const { Pool } = require('pg');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const jwt = require('jsonwebtoken');
// fetch nativo disponível no Node 18+; para versões anteriores instale node-fetch
const fetch = globalThis.fetch ?? require('node-fetch');

const app = express();

// CORS — responde preflights OPTIONS e permite credenciais cross-origin
const allowedOrigins = (process.env.ALLOWED_ORIGIN || 'http://localhost:3000')
  .split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, cb) => {
    // Permite: sem origin (same-origin/Postman), origins cadastradas, e o próprio Render
    if (!origin) return cb(null, true);
    const renderUrl = process.env.RENDER_EXTERNAL_URL || '';
    if (allowedOrigins.some(o => origin.startsWith(o)) || (renderUrl && origin.startsWith(renderUrl))) {
      return cb(null, true);
    }
    cb(new Error('CORS: origem não permitida — ' + origin));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Limite de 5 MB por requisição — cobre o maior arquivo base64 aceito em uploads.
// Base64 infla ~33 %, então 5 MB de JSON ≈ ~3,75 MB de arquivo real.
app.use(express.json({ limit: '5mb' }));

// Retorna mensagem clara quando o payload ultrapassa o limite de 5 MB.
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Arquivo muito grande. O tamanho máximo permitido por upload é 5 MB.',
    });
  }
  next(err);
});

// ─── Middleware de autenticação JWT ──────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'acerto-secret-dev';

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    req.usuario = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    req.usuario = jwt.verify(auth.slice(7), JWT_SECRET);
    if (req.usuario.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito a administradores.' });
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
        options: "-c timezone=America/Sao_Paulo",
      }
    : {
        host:     process.env.DB_HOST     || 'localhost',
        port:     process.env.DB_PORT     || 5432,
        database: process.env.DB_NAME     || 'acertos',
        user:     process.env.DB_USER     || 'postgres',
        password: process.env.DB_PASSWORD || '',
        options:  "-c timezone=America/Sao_Paulo",
      }
);

// Lista viagens em andamento do usuário autenticado
// O HTML chama GET /api/viagens
app.get('/api/viagens', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, u.nome AS tecnico, c.nome AS cliente, c.cidade,
             v.data_inicio AS "dataInicio", v.veiculo, v.adiantamento,
             v.auxiliares, v.status
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      WHERE v.status = 'Em Andamento'
        AND v.usuario_id = $1
      ORDER BY v.created_at DESC
    `, [req.usuario.id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Últimas viagens (para feed do dashboard) ─────────────────────────────────
// Dashboard chama GET /api/viagens/recentes?limit=N
app.get('/api/viagens/recentes', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const { rows } = await pool.query(`
      SELECT v.id, u.nome AS tecnico, c.nome AS cliente, c.cidade,
             v.data_inicio AS "dataInicio", v.veiculo, v.status,
             s.nome AS "servicoPrestado"
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      ORDER BY v.id DESC
      LIMIT $1
    `, [limit]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Valores distintos para os filtros do dashboard ───────────────────────────
// Dashboard chama GET /api/filtros
app.get('/api/filtros', requireAuth, async (req, res) => {
  try {
    const [tecnicos, clientes, servicos, veiculos, equipamentos] = await Promise.all([
      pool.query(`SELECT DISTINCT nome FROM usuario ORDER BY nome`),
      pool.query(`SELECT DISTINCT nome FROM cliente ORDER BY nome`),
      pool.query(`SELECT DISTINCT nome FROM servico ORDER BY nome`),
      pool.query(`SELECT DISTINCT veiculo FROM viagem WHERE veiculo IS NOT NULL AND veiculo <> '' ORDER BY veiculo`),
      pool.query(`SELECT DISTINCT equipamento FROM envio WHERE equipamento IS NOT NULL AND equipamento <> '' ORDER BY equipamento`),
    ]);
    res.json({
      tecnicos:     tecnicos.rows.map(r => r.nome),
      clientes:     clientes.rows.map(r => r.nome),
      servicos:     servicos.rows.map(r => r.nome),
      veiculos:     veiculos.rows.map(r => r.veiculo),
      equipamentos: equipamentos.rows.map(r => r.equipamento),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Busca com filtros ────────────────────────────────────────────────────────
// Dashboard chama GET /api/viagens/buscar?tecnico=&cliente=&status=&veiculo=&equipamento=&dataInicio=&dataFim=&id=
app.get('/api/viagens/buscar', requireAuth, async (req, res) => {
  try {
    const { tecnico, cliente, servico, status, veiculo, equipamento, dataInicio, dataFim, id, offset } = req.query;
    const conds  = [];
    const params = [];

    if (id)          { params.push(parseInt(id)); conds.push('v.id = $' + params.length); }
    if (tecnico)     { params.push(tecnico);       conds.push('u.nome ILIKE $' + params.length); }
    if (cliente)     { params.push(cliente);       conds.push('c.nome ILIKE $' + params.length); }
    if (servico)     { params.push(servico);       conds.push('s.nome ILIKE $' + params.length); }
    if (status)      { params.push(status);        conds.push('v.status = $' + params.length); }
    if (veiculo)     { params.push(veiculo);       conds.push('v.veiculo ILIKE $' + params.length); }
    if (equipamento) { params.push(equipamento);   conds.push(`EXISTS (SELECT 1 FROM envio en WHERE en.viagem_id = v.id AND en.equipamento ILIKE $${params.length})`); }
    if (dataInicio)  { params.push(dataInicio);    conds.push('v.data_inicio >= $' + params.length); }
    if (dataFim)     { params.push(dataFim);       conds.push('v.data_inicio <= $' + params.length); }

    const where   = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const limit   = 10;
    const off     = Math.max(0, parseInt(offset) || 0);
    const pLimit  = params.length + 1;
    const pOffset = params.length + 2;
    params.push(limit + 1); // one extra to detect hasMore
    params.push(off);

    const sql = `
      SELECT v.id, u.nome AS tecnico, c.nome AS cliente, c.cidade,
             v.data_inicio AS "dataInicio", v.veiculo, v.status,
             s.nome AS "servicoPrestado"
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      ${where}
      ORDER BY v.id DESC
      LIMIT $${pLimit} OFFSET $${pOffset}
    `;

    const { rows } = await pool.query(sql, params);
    const hasMore = rows.length > limit;
    if (hasMore) rows.pop();
    res.json({ rows, hasMore, offset: off });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// ─── Vincula (ou re-vincula) a pasta do Drive a uma viagem ───────────────────
// Dashboard chama POST /api/viagens/:id/vincular-drive
app.post('/api/viagens/:id/vincular-drive', requireAdmin, async (req, res) => {
  if (!GAS_UPLOAD_URL) {
    return res.status(500).json({ error: 'GAS_UPLOAD_URL não configurada no .env' });
  }
  const viagemId = parseInt(req.params.id);
  try {
    // Busca (ou cria) a pasta Viagem-{id} no Drive via GAS
    const gasRes  = await fetch(GAS_UPLOAD_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ viagemId, action: 'buscar_pasta' }),
    });
    const rawText = await gasRes.text();
    let gasData;
    try { gasData = JSON.parse(rawText); } catch (_) {
      return res.status(502).json({ error: 'GAS retornou resposta inválida.', gasPreview: rawText.slice(0, 200) });
    }
    if (gasData.status !== 'ok' || !gasData.link) {
      return res.status(502).json({ error: gasData.message || 'GAS não retornou link.' });
    }
    await pool.query('UPDATE viagem SET link_pasta = $1 WHERE id = $2', [gasData.link, viagemId]);
    res.json({ link: gasData.link });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Detalhes de uma viagem pelo ID
// O HTML chama GET /api/viagens/:id
app.get('/api/viagens/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, u.nome AS tecnico, c.nome AS cliente, c.cidade,
             v.data_inicio AS "dataInicio", v.veiculo, v.adiantamento, v.auxiliares,
             v.status AS "statusViagem",
             s.nome AS "servicoPrestado"
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      WHERE v.id = $1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Viagem não encontrada' });

    // Técnico só pode ver as próprias viagens; admin vê todas.
    // Comparação feita pelo usuario_id (imutável), não pelo nome (que pode mudar).
    const { rows: [ownership] } = await pool.query(
      'SELECT usuario_id FROM viagem WHERE id = $1',
      [req.params.id]
    );
    if (req.usuario.role !== 'admin' && ownership.usuario_id !== req.usuario.id) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Helpers find-or-create ───────────────────────────────────────────────────
// Nota: findOrCreateUsuario foi removido — o usuário já é identificado pelo
// token JWT (req.usuario.id), eliminando o risco de criar registros duplicados
// ou de um técnico se passar por outro apenas informando o nome no payload.

async function findOrCreateCliente(client, nome, cidade) {
  // Match on both nome AND cidade so the same client name in different
  // cities is treated as a distinct record.
  const cid = cidade || '';
  const { rows } = await client.query(
    'SELECT id FROM cliente WHERE nome = $1 AND cidade = $2 LIMIT 1',
    [nome, cid]
  );
  if (rows.length) return rows[0].id;
  const { rows: [c] } = await client.query(
    'INSERT INTO cliente (nome, cidade) VALUES ($1, $2) RETURNING id',
    [nome, cid]
  );
  return c.id;
}

async function findOrCreateCategoria(client, nome) {
  const { rows } = await client.query('SELECT id FROM despesa_categoria WHERE nome = $1 LIMIT 1', [nome]);
  if (rows.length) return rows[0].id;
  const multi = ['pedagio', 'combustivel', 'outros'];
  const tipo = multi.includes(nome) ? 'multi' : 'simples';
  const { rows: [c] } = await client.query(
    'INSERT INTO despesa_categoria (nome, tipo_despesa) VALUES ($1, $2) RETURNING id',
    [nome, tipo]
  );
  return c.id;
}

async function findOrCreateServico(client, nome) {
  if (!nome) return null;
  const { rows } = await client.query('SELECT id FROM servico WHERE nome = $1 LIMIT 1', [nome]);
  if (rows.length) return rows[0].id;
  const { rows: [s] } = await client.query(
    'INSERT INTO servico (nome) VALUES ($1) RETURNING id',
    [nome]
  );
  return s.id;
}

// ─── Cria uma viagem e retorna o ID — usado pelo HTML antes dos uploads ───────
// HTML chama POST /api/viagens/criar
app.post('/api/viagens/criar', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const b = req.body;

    // Usa o ID do usuário autenticado — não aceita nome do payload,
    // evitando que um técnico crie viagens em nome de outro.
    const usuarioId  = req.usuario.id;
    const clienteId  = await findOrCreateCliente(client, b.cliente, b.cidade);
    const servicoId  = await findOrCreateServico(client, b.servicoPrestado);

    const { rows: [v] } = await client.query(`
      INSERT INTO viagem (usuario_id, cliente_id, servico_id, data_inicio, veiculo, adiantamento, auxiliares, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
    `, [
      usuarioId,
      clienteId,
      servicoId,
      b.dataInicio,
      b.veiculo,
      parseFloat(b.adiantamento) || 0,
      b.auxiliares ? b.auxiliares.split(',').map(s => s.trim()) : [],
      b.statusViagem || 'Em Andamento',
    ]);
    const viagemId = v.id;

    await client.query('COMMIT');

    // Garante a pasta da viagem no Drive imediatamente (sem arquivo) e salva o link
    if (GAS_UPLOAD_URL) {
      try {
        const gasRes  = await fetch(GAS_UPLOAD_URL, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ viagemId, dataNFs: b.dataInicio }),
        });
        const gasData = await gasRes.json().catch(() => null);
        if (gasData?.status === 'ok' && gasData.link) {
          await pool.query('UPDATE viagem SET link_pasta = $1 WHERE id = $2', [gasData.link, viagemId]);
        } else {
          console.warn('Aviso: GAS não retornou link válido ao criar viagem:', gasData);
        }
      } catch (e) {
        console.warn('Aviso: não foi possível criar pasta no Drive:', e.message);
      }
    }

    res.json({ viagemId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ─── Proxy de upload: recebe base64 do HTML e envia ao GAS ───────────────────
// O navegador não consegue chamar o GAS diretamente por restrições de CORS.
// O server.js faz a chamada server-side, sem essas restrições.
// HTML chama POST /api/upload
const GAS_UPLOAD_URL = process.env.GAS_UPLOAD_URL || '';

app.post('/api/upload', requireAuth, async (req, res) => {
  if (!GAS_UPLOAD_URL) {
    return res.status(500).json({ error: 'GAS_UPLOAD_URL não configurada no .env' });
  }

  // Valida tamanho do arquivo base64 antes de encaminhar ao GAS.
  // Base64 representa 3 bytes em 4 caracteres → tamanho_real ≈ length * 0.75
  const base64 = req.body?.fileData ?? req.body?.base64 ?? '';
  const estimatedBytes = Math.ceil(base64.length * 0.75);
  const MAX_BYTES = 5 * 1024 * 1024; // 5 MB
  if (estimatedBytes > MAX_BYTES) {
    return res.status(413).json({
      error: 'Arquivo muito grande. O tamanho máximo permitido por upload é 5 MB.',
    });
  }
  try {
    const response = await fetch(GAS_UPLOAD_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(req.body),
    });

    // Lê o corpo como texto primeiro para diagnóstico — o GAS às vezes
    // retorna uma página HTML de erro em vez de JSON (ex.: timeout, quota).
    const rawText = await response.text();

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (_) {
      // GAS retornou algo que não é JSON (página de erro, HTML, etc.)
      console.error('GAS retornou resposta não-JSON (status HTTP', response.status, '):\n', rawText.slice(0, 500));
      return res.status(502).json({
        error: `GAS retornou resposta inválida (HTTP ${response.status}). Verifique os logs do Apps Script.`,
        gasPreview: rawText.slice(0, 200),
      });
    }

    if (data.status !== 'ok') {
      console.error('GAS retornou status de erro:', data);
      throw new Error(data.message || `GAS status: ${data.status}`);
    }

    if (!data.link) {
      console.error('GAS retornou status ok mas sem link:', data);
      throw new Error('GAS não retornou o link do arquivo.');
    }

    res.json({ link: data.link });
  } catch (err) {
    console.error('Erro no upload para o Drive:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Registra um novo envio (ou cria a viagem se for nova) ────────────────────
// O HTML chama POST /api/acertos
// Os campos despesas.single[x].file e despesas.multi[x][].file chegam como
// links do Google Drive (ex: https://drive.google.com/...) — o GAS já fez o upload.
app.post('/api/acertos', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const b = req.body;

    // Usa o ID do usuário autenticado — não aceita nome do payload.
    const usuarioId = req.usuario.id;
    let viagemId = b.viagemId;

    // Se for nova viagem, cria primeiro.
    // Usa um advisory lock baseado no hash (usuario_id, cliente, data) para serializar
    // requisições idênticas em paralelo (ex: duplo clique antes de obter o viagemId).
    if (!viagemId) {
      const clienteId = await findOrCreateCliente(client, b.cliente, b.cidade);
      const servicoId = await findOrCreateServico(client, b.servicoPrestado);

      const { rows: [v] } = await client.query(`
        INSERT INTO viagem (usuario_id, cliente_id, servico_id, data_inicio, veiculo, adiantamento, auxiliares, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
      `, [
        usuarioId,
        clienteId,
        servicoId,
        b.dataInicio,
        b.veiculo,
        parseFloat(b.adiantamento) || 0,
        b.auxiliares ? b.auxiliares.split(',').map(s => s.trim()) : [],
        b.statusViagem || 'Em Andamento',
      ]);
      viagemId = v.id;
    } else {
      // Viagem existente: trava a linha para evitar condição de corrida entre
      // dois envios simultâneos (ex: duplo clique ou abas concorrentes).
      const { rows: ownership } = await client.query(
        'SELECT usuario_id FROM viagem WHERE id = $1 FOR UPDATE',
        [viagemId]
      );
      if (!ownership.length) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Viagem não encontrada.' });
      }
      if (req.usuario.role !== 'admin' && ownership[0].usuario_id !== req.usuario.id) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'Acesso negado.' });
      }
      // Atualiza status sempre que vier no payload
      if (b.statusViagem) {
        await client.query(
          'UPDATE viagem SET status = $1 WHERE id = $2',
          [b.statusViagem, viagemId]
        );
      }
    }

    // Cria o envio do dia.
    // O SELECT FOR UPDATE acima serializa envios concorrentes para a mesma
    // viagem: o segundo aguarda o COMMIT/ROLLBACK do primeiro antes de prosseguir,
    // garantindo que não sejam criados dois envios duplicados num mesmo instante.
    const { rows: [envio] } = await client.query(`
      INSERT INTO envio (viagem_id, usuario_id, data_nfs, equipamento, observacoes, assinatura_arquivo)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
    `, [
      viagemId,
      usuarioId,
      b.dataNFs     || null,
      b.equipamento || null,
      b.observacoes || '',
      b.signature   || '',
    ]);

    // Insere despesas simples (café, almoço, janta, hotel)
    for (const [nome, d] of Object.entries(b.despesas?.single || {})) {
      if (!d.file) continue;
      const catId = await findOrCreateCategoria(client, nome);
      await client.query(`
        INSERT INTO despesa (envio_id, categoria_id, valor, pagamento, arquivo, slot_numero)
        VALUES ($1, $2, $3, $4, $5, NULL)
      `, [envio.id, catId, parseFloat(d.valor) || 0, d.pay || '', d.file]);
    }

    // Insere despesas múltiplas (pedágio, combustível, outros)
    for (const [nome, slots] of Object.entries(b.despesas?.multi || {})) {
      for (const s of slots) {
        if (!s.file) continue;
        const catId = await findOrCreateCategoria(client, nome);
        await client.query(`
          INSERT INTO despesa (envio_id, categoria_id, valor, pagamento, arquivo, slot_numero)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [envio.id, catId, parseFloat(s.valor) || 0, s.pay || '', s.file, s.slot]);
      }
    }

    await client.query('COMMIT');

    // Para viagens novas criadas inline, tenta criar pasta no Drive e salvar link
    if (!b.viagemId && GAS_UPLOAD_URL) {
      try {
        const gasRes  = await fetch(GAS_UPLOAD_URL, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ viagemId, dataNFs: b.dataInicio }),
        });
        const gasData = await gasRes.json().catch(() => null);
        if (gasData?.status === 'ok' && gasData.link) {
          await pool.query('UPDATE viagem SET link_pasta = $1 WHERE id = $2', [gasData.link, viagemId]);
        }
      } catch (e) {
        console.warn('Aviso: não foi possível criar pasta no Drive (acertos):', e.message);
      }
    }

    res.json({ viagemId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});



// ─── Clientes e cidades para os selects do formulário ────────────────────────
// Retorna todos os pares (nome, cidade) distintos ordenados por nome
app.get('/api/clientes', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT nome, cidade
      FROM cliente
      ORDER BY nome ASC, cidade ASC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// Lista usuários ativos para o select do login (sem expor senha)
app.get('/api/auth/usuarios', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, nome, role FROM usuario WHERE ativo = TRUE ORDER BY nome`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { usuarioId, senha } = req.body;
  if (!usuarioId || !senha) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });
  try {
    const { rows } = await pool.query(
      'SELECT id, nome, role, senha_hash FROM usuario WHERE id = $1 AND ativo = TRUE',
      [usuarioId]
    );
    if (!rows.length) return res.status(401).json({ error: 'Usuário não encontrado.' });
    const usuario = rows[0];
    if (!usuario.senha_hash) return res.status(401).json({ error: 'Usuário sem senha cadastrada. Contate o administrador.' });
    const ok = await bcrypt.compare(senha, usuario.senha_hash);
    if (!ok) return res.status(401).json({ error: 'Senha incorreta.' });
    const token = jwt.sign(
      { id: usuario.id, nome: usuario.nome, role: usuario.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, nome: usuario.nome, role: usuario.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Logout — JWT é stateless, o cliente apenas descarta o token
app.post('/api/auth/logout', (req, res) => {
  res.json({ ok: true });
});

// Valida token e retorna dados do usuário (usado pelas páginas ao carregar)
app.get('/api/auth/me', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    const usuario = jwt.verify(auth.slice(7), JWT_SECRET);
    res.json({ id: usuario.id, nome: usuario.nome, role: usuario.role });
  } catch (e) {
    res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
});

// ─── CRUD de usuários (somente admin) ────────────────────────────────────────

// Lista todos os usuários
app.get('/api/admin/usuarios', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, nome, role, ativo FROM usuario ORDER BY nome`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Cria um novo usuário
app.post('/api/admin/usuarios', requireAdmin, async (req, res) => {
  const { nome, senha, role } = req.body;
  if (!nome || !nome.trim())   return res.status(400).json({ error: 'Nome é obrigatório.' });
  if (!senha || !senha.trim()) return res.status(400).json({ error: 'Senha é obrigatória.' });
  const roleVal = role === 'admin' ? 'admin' : 'tecnico';
  try {
    const senha_hash = await bcrypt.hash(senha, 12);
    const { rows: [u] } = await pool.query(
      `INSERT INTO usuario (nome, senha_hash, role, ativo) VALUES ($1, $2, $3, TRUE) RETURNING id, nome, role, ativo`,
      [nome.trim(), senha_hash, roleVal]
    );
    res.status(201).json(u);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Atualiza nome, senha, role e/ou status de um usuário
app.patch('/api/admin/usuarios/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'ID inválido.' });

  const { nome, senha, role, ativo } = req.body;
  const sets   = [];
  const params = [];

  if (nome !== undefined) {
    if (!nome.trim()) return res.status(400).json({ error: 'Nome não pode ser vazio.' });
    params.push(nome.trim()); sets.push(`nome = $${params.length}`);
  }
  if (senha !== undefined && senha.trim()) {
    const hash = await bcrypt.hash(senha.trim(), 12);
    params.push(hash); sets.push(`senha_hash = $${params.length}`);
  }
  if (role !== undefined) {
    const roleVal = role === 'admin' ? 'admin' : 'tecnico';
    params.push(roleVal); sets.push(`role = $${params.length}`);
  }
  if (ativo !== undefined) {
    params.push(Boolean(ativo)); sets.push(`ativo = $${params.length}`);
  }

  if (!sets.length) return res.status(400).json({ error: 'Nenhum campo para atualizar.' });

  params.push(id);
  try {
    const { rows } = await pool.query(
      `UPDATE usuario SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING id, nome, role, ativo`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Usuário não encontrado.' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Serve os HTMLs estáticos da pasta public/
app.use(express.static(path.join(__dirname, 'public')));

// Rota raiz → login
app.get('/', (req, res) => res.redirect('/login.html'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));
// ─── Resumo completo de uma viagem para o dashboard ──────────────────────────
// Dashboard chama GET /api/viagens/:id/resumo
app.get('/api/viagens/:id/resumo', requireAdmin, async (req, res) => {
  try {
    // Dados gerais da viagem
    const { rows: [viagem] } = await pool.query(`
      SELECT
        v.id, v.data_inicio AS "dataInicio", v.veiculo, v.adiantamento,
        v.auxiliares, v.status, v.link_pasta AS "linkPasta",
        u.nome AS tecnico,
        c.nome AS cliente, c.cidade,
        s.nome AS "servicoPrestado",
        (
          SELECT en2.equipamento
          FROM envio en2
          WHERE en2.viagem_id = v.id AND en2.equipamento IS NOT NULL
          ORDER BY en2.id DESC
          LIMIT 1
        ) AS equipamento
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      WHERE v.id = $1
      LIMIT 1
    `, [req.params.id]);

    if (!viagem) return res.status(404).json({ error: 'Viagem não encontrada' });

    // Envios com suas despesas agrupadas
    const { rows: envios } = await pool.query(`
      SELECT
        en.id AS envio_id,
        en.data_nfs AS "dataNFs",
        en.equipamento,
        en.observacoes,
        en.timestamp,
        dc.nome AS categoria,
        dc.tipo_despesa AS tipo,
        d.valor,
        d.pagamento,
        d.slot_numero AS slot
      FROM envio en
      LEFT JOIN despesa d ON d.envio_id = en.id
      LEFT JOIN despesa_categoria dc ON dc.id = d.categoria_id
      WHERE en.viagem_id = $1
      ORDER BY en.data_nfs ASC, en.id ASC, d.slot_numero ASC NULLS FIRST
    `, [req.params.id]);

    // Agrupa despesas por envio
    const enviosMap = {};
    for (const row of envios) {
      if (!enviosMap[row.envio_id]) {
        enviosMap[row.envio_id] = {
          envioId:     row.envio_id,
          dataNFs:     row.dataNFs,
          equipamento: row.equipamento || null,
          observacoes: row.observacoes,
          timestamp:   row.timestamp,
          despesas:    { cafe: null, almoco: null, janta: null, hotel: null, pedagio: [], combustivel: [], outros: [] }
        };
      }
      if (!row.categoria) continue;
      const cat = row.categoria.toLowerCase();
      const entry = { valor: parseFloat(row.valor) || 0, pagamento: row.pagamento || '' };
      if (['cafe','almoco','janta','hotel'].includes(cat)) {
        enviosMap[row.envio_id].despesas[cat] = entry;
      } else if (['pedagio','combustivel','outros'].includes(cat)) {
        enviosMap[row.envio_id].despesas[cat].push({ ...entry, slot: row.slot });
      }
    }

    // Calcula totais por forma de pagamento
    let totalPix = 0, totalCorp = 0;
    const linhasEnvio = Object.values(enviosMap);

    for (const en of linhasEnvio) {
      const d = en.despesas;
      for (const cat of ['cafe','almoco','janta','hotel']) {
        if (!d[cat]) continue;
        if (d[cat].pagamento === 'dinheiro_pix') totalPix  += d[cat].valor;
        if (d[cat].pagamento === 'cartao_corp')  totalCorp += d[cat].valor;
      }
      for (const cat of ['pedagio','combustivel','outros']) {
        for (const slot of d[cat]) {
          if (slot.pagamento === 'dinheiro_pix') totalPix  += slot.valor;
          if (slot.pagamento === 'cartao_corp')  totalCorp += slot.valor;
        }
      }
    }

    res.json({
      viagem,
      envios: linhasEnvio,
      totais: {
        pix:   parseFloat(totalPix.toFixed(2)),
        corp:  parseFloat(totalCorp.toFixed(2)),
        geral: parseFloat((totalPix + totalCorp).toFixed(2))
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
