const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();

// --- CONFIGURAÇÕES ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

app.use(session({
    secret: 'chave-secreta-faculdade',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, 'uploads/'); },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + ext);
    }
});
const upload = multer({ storage: storage });

// --- UTILITÁRIOS E MIDDLEWARES ---
const validarEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const verificarLogin = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ erro: "Sessão expirada." });
    next();
};

const verificarProfessor = (req, res, next) => {
    if (req.session.tipo !== 'professor') return res.status(403).json({ erro: "Acesso negado." });
    next();
};

// --- AUTENTICAÇÃO ---
app.post('/auth/register', async (req, res) => {
    let { tipo, nome, email, senha, ra, turma } = req.body;
    if(!validarEmail(email)) return res.redirect('/login.html?erro=email_invalido');
    email = email.toLowerCase().trim();

    try {
        const finalizarCadastro = async () => {
            const senhaHash = await bcrypt.hash(senha, 10);
            const sql = "INSERT INTO usuarios (nome, email, senha, ra, turma, tipo) VALUES (?, ?, ?, ?, ?, ?)";
            db.query(sql, [nome, email, senhaHash, ra || null, turma || null, tipo], (err, result) => {
                if (err) {
                    if (err.message.includes('usuarios.ra') || err.code === 'ER_DUP_ENTRY') {
                        return res.redirect('/login.html?erro=ra_duplicado');
                    }
                    return res.redirect('/login.html?erro=email_ja_cadastrado');
                }
                req.session.userId = result.insertId;
                req.session.email = email;
                req.session.tipo = tipo;
                req.session.nome = nome;
                req.session.ra = ra || null;
                res.redirect(tipo === 'aluno' ? '/dashboard-aluno.html' : '/dashboard-prof.html');
            });
        };

        if (tipo === 'professor') {
            db.query("SELECT * FROM professores_autorizados WHERE email = ?", [email], (err, results) => {
                if (err || results.length === 0) return res.redirect('/login.html?erro=email_nao_autorizado');
                finalizarCadastro();
            });
        } else {
            finalizarCadastro();
        }
    } catch (e) { res.redirect('/login.html?erro=interno'); }
});

app.post('/auth/login', (req, res) => {
    let { email, senha } = req.body;
    email = email.toLowerCase().trim();
    db.query("SELECT * FROM usuarios WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.redirect('/login.html?erro=usuario_nao_encontrado');
        const user = results[0];
        if (await bcrypt.compare(senha, user.senha)) {
            req.session.userId = user.id;
            req.session.email = user.email;
            req.session.tipo = user.tipo;
            req.session.nome = user.nome;
            req.session.ra = user.ra; 
            return res.redirect(user.tipo === 'aluno' ? '/dashboard-aluno.html' : '/dashboard-prof.html');
        }
        res.redirect('/login.html?erro=senha_incorreta');
    });
});

// --- ATIVIDADES (ALUNO) ---
app.post('/enviar-atividade', verificarLogin, upload.single('arquivo'), (req, res) => {
    if (!req.file) return res.status(400).json({erro: "Arquivo não enviado"});
    const sql = "INSERT INTO atividades (id_aluno, nome_arquivo, caminho_arquivo) VALUES (?, ?, ?)";
    db.query(sql, [req.session.userId, req.file.originalname, req.file.filename], (err) => {
        if (err) return res.status(500).json({erro: "Erro ao salvar no banco"});
        res.json({sucesso: true});
    });
});

app.get('/aluno/minhas-atividades', verificarLogin, (req, res) => {
    const sql = "SELECT *, data_correcao FROM atividades WHERE id_aluno = ? ORDER BY data_envio DESC";
    db.query(sql, [req.session.userId], (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// --- ATIVIDADES (PROFESSOR) ---
app.get('/atividades/lista', verificarLogin, verificarProfessor, (req, res) => {
    const sql = `
        SELECT atividades.*, usuarios.nome AS nome_aluno, usuarios.ra AS ra_aluno, usuarios.turma AS sala_aluno
        FROM atividades 
        JOIN usuarios ON atividades.id_aluno = usuarios.id 
        ORDER BY atividades.data_envio DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// ATUALIZADO: Rota de correção com trava para apenas números
app.post('/atividades/corrigir', verificarLogin, verificarProfessor, (req, res) => {
    const { id, nota, feedback, data_correcao } = req.body;
    
    // Converte vírgula em ponto e tenta transformar em número
    const notaLimpa = String(nota).replace(',', '.');
    const notaNumerica = parseFloat(notaLimpa);

    // Validação rigorosa: verifica se é um número válido e se está no intervalo acadêmico
    if (isNaN(notaNumerica) || notaNumerica < 0 || notaNumerica > 10) {
        return res.status(400).json({ sucesso: false, erro: "A nota deve ser um número entre 0 e 10." });
    }

    const sql = "UPDATE atividades SET nota = ?, feedback = ?, corrigido = TRUE, data_correcao = ? WHERE id = ?";
    db.query(sql, [notaNumerica, feedback, data_correcao, id], (err) => {
        if (err) return res.status(500).json({ sucesso: false, erro: "Erro ao salvar no banco." });
        res.json({ sucesso: true });
    });
});

// --- PERFIL ---
app.get('/api/perfil', verificarLogin, (req, res) => {
    db.query("SELECT id, nome, email, ra, tipo, foto FROM usuarios WHERE id = ?", [req.session.userId], (err, results) => {
        if (err || results.length === 0) return res.status(500).json({erro: "Erro ao buscar perfil"});
        res.json(results[0]);
    });
});

app.post('/auth/atualizar-foto', verificarLogin, upload.single('foto'), (req, res) => {
    if (!req.file) return res.status(400).json({erro: "Arquivo não enviado"});
    const fotoPath = '/uploads/' + req.file.filename;
    db.query("UPDATE usuarios SET foto = ? WHERE id = ?", [fotoPath, req.session.userId], (err) => {
        if (err) return res.status(500).json({erro: "Erro ao salvar foto"});
        res.json({ sucesso: true, url: fotoPath });
    });
});

app.get('/auth/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));