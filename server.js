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
    saveUninitialized: true
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

// --- AUTENTICAÇÃO ---

app.post('/auth/register', async (req, res) => {
    const { tipo, nome, email, senha, ra, turma } = req.body;
    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        const sql = "INSERT INTO usuarios (nome, email, senha, ra, turma, tipo) VALUES (?, ?, ?, ?, ?, ?)";
        db.query(sql, [nome, email, senhaHash, ra || null, turma || null, tipo], (err) => {
            if (err) return res.status(500).send("Erro ao cadastrar.");
            res.send("<h1>Cadastro ok!</h1><a href='/login.html'>Login</a>");
        });
    } catch (e) { res.status(500).send("Erro interno."); }
});

app.post('/auth/login', (req, res) => {
    const { email, senha } = req.body;
    db.query("SELECT * FROM usuarios WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.send("Utilizador não encontrado.");
        const user = results[0];
        if (await bcrypt.compare(senha, user.senha)) {
            req.session.userId = user.id;
            req.session.tipo = user.tipo;
            req.session.nome = user.nome;
            return user.tipo === 'aluno' ? res.redirect('/dashboard-aluno.html') : res.redirect('/dashboard-prof.html');
        }
        res.send("Senha incorreta.");
    });
});

// --- ROTAS DO ALUNO ---

// NOVA ROTA: ALTERAR SENHA COM BCRYPT
app.post('/aluno/trocar-senha', async (req, res) => {
    const { novaSenha } = req.body;
    const id_usuario = req.session.userId;

    if (!id_usuario) return res.status(401).json({ erro: "Não autorizado." });
    if (!novaSenha || novaSenha.length < 4) return res.status(400).json({ erro: "Senha muito curta." });

    try {
        // Importante: Gerar hash para a nova senha
        const novaSenhaHash = await bcrypt.hash(novaSenha, 10);
        const sql = "UPDATE usuarios SET senha = ? WHERE id = ?";
        
        db.query(sql, [novaSenhaHash, id_usuario], (err) => {
            if (err) return res.status(500).json({ erro: "Erro no banco de dados." });
            res.json({ sucesso: true, mensagem: "Senha alterada com sucesso!" });
        });
    } catch (e) {
        res.status(500).json({ erro: "Erro ao processar senha." });
    }
});

app.post('/enviar-atividade', upload.single('arquivo'), (req, res) => {
    if (!req.file) return res.status(400).send("Nenhum arquivo enviado.");
    const id_aluno = req.session.userId;
    if (!id_aluno) return res.status(401).send("Sessão expirada.");

    const sql = "INSERT INTO atividades (id_aluno, nome_arquivo, caminho_arquivo) VALUES (?, ?, ?)";
    db.query(sql, [id_aluno, req.file.originalname, req.file.filename], (err) => {
        if (err) return res.status(500).send("Erro ao salvar no banco.");
        res.send("<h1>Enviado com sucesso!</h1><a href='/dashboard-aluno.html'>Voltar</a>");
    });
});

app.get('/aluno/minhas-atividades', (req, res) => {
    const id_aluno = req.session.userId;
    if (!id_aluno) return res.status(401).json([]);

    db.query("SELECT * FROM atividades WHERE id_aluno = ? ORDER BY data_envio DESC", [id_aluno], (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// --- ROTAS DO PROFESSOR ---

app.get('/atividades/lista', (req, res) => {
    const sql = `
        SELECT atividades.*, usuarios.nome AS nome_aluno, usuarios.ra AS ra_aluno 
        FROM atividades 
        JOIN usuarios ON atividades.id_aluno = usuarios.id 
        ORDER BY atividades.data_envio DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

app.post('/atividades/corrigir', (req, res) => {
    const { id, nota, feedback } = req.body;
    const sql = "UPDATE atividades SET nota = ?, feedback = ?, corrigido = TRUE WHERE id = ?";
    db.query(sql, [nota, feedback, id], (err) => {
        if (err) return res.status(500).json({sucesso: false});
        res.json({sucesso: true});
    });
});

app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));