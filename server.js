if (process.env.NODE_ENV !== 'production') require('dotenv').config();
const express  = require('express');
const path     = require('path');
const { Pool } = require('pg');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const session  = require('express-session');
// fetch nativo disponível no Node 18+; para versões anteriores instale node-fetch
const fetch = globalThis.fetch ?? require('node-fetch');

const app = express();

// CORS — responde preflights OPTIONS e permite credenciais cross-origin
const allowedOrigins = (process.env.ALLOWED_ORIGIN || 'http://localhost:3000')
  .split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, cb) => {
    // Permite requisições sem origin (ex: Postman, curl) e origins cadastradas
    if (!origin || allowedOrigins.some(o => origin.startsWith(o))) return cb(null, true);
    cb(new Error('CORS: origem não permitida — ' + origin));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Responde preflights explicitamente (necessário para cookies cross-origin)
app.options('/{*path}', cors());
app.use(express.json({ limit: '20mb' }));

// Sessão httpOnly — cookie seguro, não acessível por JS no browser
app.use(session({
  secret:            process.env.SESSION_SECRET || 'acerto-secret-dev',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   true,       // HTTPS obrigatório em produção
    sameSite: 'none',     // Necessário para cross-origin (GitHub Pages → Render)
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

// ─── Middleware de autenticação ───────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session?.usuario) return res.status(401).json({ error: 'Não autenticado.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.usuario) return res.status(401).json({ error: 'Não autenticado.' });
  if (req.session.usuario.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  next();
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
      ORDER BY v.created_at DESC
    `);
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
      pool.query(`SELECT DISTINCT modelo FROM equipamento WHERE modelo IS NOT NULL AND modelo <> '' ORDER BY modelo`),
    ]);
    res.json({
      tecnicos:     tecnicos.rows.map(r => r.nome),
      clientes:     clientes.rows.map(r => r.nome),
      servicos:     servicos.rows.map(r => r.nome),
      veiculos:     veiculos.rows.map(r => r.veiculo),
      equipamentos: equipamentos.rows.map(r => r.modelo),
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
    if (equipamento) { params.push(equipamento);   conds.push('e.modelo ILIKE $' + params.length); }
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
      LEFT JOIN viagem_equipamento ve ON ve.viagem_id = v.id
      LEFT JOIN equipamento e ON e.id = ve.equipamento_id
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
// Detalhes de uma viagem pelo ID
// O HTML chama GET /api/viagens/:id
app.get('/api/viagens/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, u.nome AS tecnico, c.nome AS cliente, c.cidade,
             v.data_inicio AS "dataInicio", v.veiculo, v.adiantamento, v.auxiliares,
             s.nome AS "servicoPrestado"
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      WHERE v.id = $1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Viagem não encontrada' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Helpers find-or-create ───────────────────────────────────────────────────

async function findOrCreateUsuario(client, nome) {
  const { rows } = await client.query('SELECT id FROM usuario WHERE nome = $1 LIMIT 1', [nome]);
  if (rows.length) return rows[0].id;
  const { rows: [u] } = await client.query(
    'INSERT INTO usuario (nome) VALUES ($1) RETURNING id',
    [nome]
  );
  return u.id;
}

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

async function findOrCreateEquipamento(client, clienteId, modelo, numSerie) {
  if (!modelo) return null;
  const ns = numSerie || null;
  // num_serie may be null — must use IS NULL instead of = null in WHERE
  const selectSql = ns !== null
    ? 'SELECT id FROM equipamento WHERE modelo = $1 AND cliente_id = $2 AND num_serie = $3 LIMIT 1'
    : 'SELECT id FROM equipamento WHERE modelo = $1 AND cliente_id = $2 AND num_serie IS NULL LIMIT 1';
  const selectParams = ns !== null ? [modelo, clienteId, ns] : [modelo, clienteId];
  const { rows } = await client.query(selectSql, selectParams);
  if (rows.length) return rows[0].id;
  const { rows: [e] } = await client.query(
    'INSERT INTO equipamento (modelo, num_serie, cliente_id) VALUES ($1, $2, $3) RETURNING id',
    [modelo, ns, clienteId]
  );
  return e.id;
}

// ─── Cria uma viagem e retorna o ID — usado pelo HTML antes dos uploads ───────
// HTML chama POST /api/viagens/criar
app.post('/api/viagens/criar', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const b = req.body;

    const usuarioId  = await findOrCreateUsuario(client, b.tecnico);
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

    if (b.equipamento) {
      const equipamentoId = await findOrCreateEquipamento(client, clienteId, b.equipamento, b.numSerie || null);
      if (equipamentoId) {
        await client.query(
          'INSERT INTO viagem_equipamento (viagem_id, equipamento_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [viagemId, equipamentoId]
        );
      }
    }

    await client.query('COMMIT');

    // Garante a pasta da viagem no Drive imediatamente (sem arquivo)
    if (GAS_UPLOAD_URL) {
      try {
        await fetch(GAS_UPLOAD_URL, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ viagemId, dataNFs: b.dataInicio }),
        });
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
  try {
    const response = await fetch(GAS_UPLOAD_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(req.body),
    });
    const data = await response.json();
    if (data.status !== 'ok') throw new Error(data.message || 'Erro no GAS');
    res.json({ link: data.link });
  } catch (err) {
    console.error('Erro no upload para o Drive:', err);
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

    const usuarioId = await findOrCreateUsuario(client, b.tecnico);
    let viagemId = b.viagemId;

    // Se for nova viagem, cria primeiro
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

      // Vincula equipamento (se informado)
      if (b.equipamento) {
        const equipamentoId = await findOrCreateEquipamento(client, clienteId, b.equipamento, b.numSerie || null);
        if (equipamentoId) {
          await client.query(
            'INSERT INTO viagem_equipamento (viagem_id, equipamento_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [viagemId, equipamentoId]
          );
        }
      }
    } else {
      // Viagem existente: atualiza status sempre que vier no payload
      if (b.statusViagem) {
        await client.query(
          'UPDATE viagem SET status = $1 WHERE id = $2',
          [b.statusViagem, viagemId]
        );
      }
    }

    // Cria o envio do dia
    const { rows: [envio] } = await client.query(`
      INSERT INTO envio (viagem_id, usuario_id, data_nfs, observacoes, assinatura_arquivo)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, [
      viagemId,
      usuarioId,
      b.dataNFs     || null,
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
    req.session.usuario = { id: usuario.id, nome: usuario.nome, role: usuario.role };
    res.json({ nome: usuario.nome, role: usuario.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Retorna sessão atual (usado pelas páginas ao carregar)
app.get('/api/auth/me', (req, res) => {
  if (!req.session?.usuario) return res.status(401).json({ error: 'Não autenticado.' });
  res.json(req.session.usuario);
});

// Rota raiz — health check para o Render confirmar que o serviço está no ar
app.get('/', (req, res) => res.json({ status: 'ok' }));

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
        v.auxiliares, v.status,
        u.nome AS tecnico,
        c.nome AS cliente, c.cidade,
        s.nome AS "servicoPrestado",
        e.modelo AS equipamento, e.num_serie AS "numSerie"
      FROM viagem v
      JOIN usuario u ON u.id = v.usuario_id
      JOIN cliente c ON c.id = v.cliente_id
      LEFT JOIN servico s ON s.id = v.servico_id
      LEFT JOIN viagem_equipamento ve ON ve.viagem_id = v.id
      LEFT JOIN equipamento e ON e.id = ve.equipamento_id
      WHERE v.id = $1
      LIMIT 1
    `, [req.params.id]);

    if (!viagem) return res.status(404).json({ error: 'Viagem não encontrada' });

    // Envios com suas despesas agrupadas
    const { rows: envios } = await pool.query(`
      SELECT
        en.id AS envio_id,
        en.data_nfs AS "dataNFs",
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
