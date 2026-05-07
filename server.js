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

// --- UTILITÁRIOS ---
const validarEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

// --- MIDDLEWARES DE SEGURANÇA ---
const verificarLogin = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ erro: "Sessão expirada." });
    next();
};

const verificarProfessor = (req, res, next) => {
    if (req.session.tipo !== 'professor') return res.status(403).json({ erro: "Acesso negado." });
    next();
};

// Middleware para proteger rotas administrativas
const verificarAdmin = (req, res, next) => {
    const adminsPermitidos = ['gustavo@gmail.com', 'admin@faculdade.com']; 
    
    // Pegamos o email da sessão e limpamos ele para garantir a comparação
    const emailSessao = req.session.email ? req.session.email.toLowerCase().trim() : null;

    console.log(`[Segurança] Tentativa de acesso admin por: ${emailSessao}`);

    if (req.session.userId && emailSessao && adminsPermitidos.includes(emailSessao)) {
        return next();
    }
    
    console.log(`[Aviso] Acesso Admin bloqueado para: ${emailSessao}`);
    res.status(403).json({ erro: "Acesso administrativo negado." });
};

// --- ADMINISTRAÇÃO DE ACESSOS (PROTEGIDO) ---
app.get('/admin/lista-autorizados', verificarLogin, verificarAdmin, (req, res) => {
    db.query("SELECT * FROM professores_autorizados ORDER BY adicionado_em DESC", (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

app.post('/admin/autorizar-professor', verificarLogin, verificarAdmin, (req, res) => {
    let { email } = req.body;
    if(!email || !validarEmail(email)) return res.status(400).json({erro: "E-mail inválido ou obrigatório"});
    
    email = email.toLowerCase().trim();

    db.query("INSERT INTO professores_autorizados (email) VALUES (?)", [email], (err) => {
        if (err) return res.status(500).json({ erro: "Email já autorizado ou erro no banco." });
        res.json({ sucesso: true });
    });
});

app.delete('/admin/remover-autorizacao/:id', verificarLogin, verificarAdmin, (req, res) => {
    db.query("DELETE FROM professores_autorizados WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ erro: "Erro ao remover." });
        res.json({ sucesso: true });
    });
});

// --- AUTENTICAÇÃO ---
app.post('/auth/register', async (req, res) => {
    let { tipo, nome, email, senha, ra, turma } = req.body;
    
    if(!validarEmail(email)) return res.redirect('/login.html?erro=email_invalido');
    email = email.toLowerCase().trim();

    try {
        if (tipo === 'professor') {
            const checkSql = "SELECT * FROM professores_autorizados WHERE email = ?";
            db.query(checkSql, [email], async (err, results) => {
                if (err || results.length === 0) {
                    return res.redirect('/login.html?erro=email_nao_autorizado');
                }
                finalizarCadastro();
            });
        } else {
            finalizarCadastro();
        }

        async function finalizarCadastro() {
            const senhaHash = await bcrypt.hash(senha, 10);
            const sql = "INSERT INTO usuarios (nome, email, senha, ra, turma, tipo) VALUES (?, ?, ?, ?, ?, ?)";
            
            db.query(sql, [nome, email, senhaHash, ra || null, turma || null, tipo], (err, result) => {
                if (err) return res.redirect('/login.html?erro=email_ja_cadastrado');

                req.session.userId = result.insertId;
                req.session.email = email.toLowerCase().trim(); // Normalizado
                req.session.tipo = tipo;
                req.session.nome = nome;
                req.session.ra = ra || null;

                res.redirect(tipo === 'aluno' ? '/dashboard-aluno.html' : '/dashboard-prof.html');
            });
        }
    } catch (e) { 
        res.redirect('/login.html?erro=interno');
    }
});

app.post('/auth/login', (req, res) => {
    let { email, senha } = req.body;
    email = email.toLowerCase().trim();

    db.query("SELECT * FROM usuarios WHERE email = ?", [email], async (err, results) => {
        if (err || results.length === 0) return res.redirect('/login.html?erro=usuario_nao_encontrado');
        
        const user = results[0];
        if (await bcrypt.compare(senha, user.senha)) {
            req.session.userId = user.id;
            req.session.email = user.email.toLowerCase().trim(); // Garantia de normalização
            req.session.tipo = user.tipo;
            req.session.nome = user.nome;
            req.session.ra = user.ra; 
            
            console.log(`[Login] Usuário ${req.session.email} logado com sucesso.`);
            return res.redirect(user.tipo === 'aluno' ? '/dashboard-aluno.html' : '/dashboard-prof.html');
        }
        res.redirect('/login.html?erro=senha_incorreta');
    });
});

app.get('/auth/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

// --- PERFIL ---
app.get('/api/perfil', verificarLogin, (req, res) => {
    res.json({
        id: req.session.userId,
        nome: req.session.nome,
        email: req.session.email,
        ra: req.session.ra || null,
        tipo: req.session.tipo
    });
});

app.post('/auth/trocar-senha', verificarLogin, async (req, res) => {
    const { novaSenha } = req.body;
    if (!novaSenha || novaSenha.length < 4) return res.status(400).json({ erro: "Senha muito curta." });

    try {
        const novaSenhaHash = await bcrypt.hash(novaSenha, 10);
        db.query("UPDATE usuarios SET senha = ? WHERE id = ?", [novaSenhaHash, req.session.userId], (err) => {
            if (err) return res.status(500).json({ erro: "Erro no banco." });
            res.json({ sucesso: true });
        });
    } catch (e) { res.status(500).json({ erro: "Erro ao processar." }); }
});

// --- ALUNO ---
app.post('/enviar-atividade', verificarLogin, upload.single('arquivo'), (req, res) => {
    if (!req.file) return res.status(400).json({erro: "Arquivo não enviado"});
    
    const sql = "INSERT INTO atividades (id_aluno, nome_arquivo, caminho_arquivo) VALUES (?, ?, ?)";
    db.query(sql, [req.session.userId, req.file.originalname, req.file.filename], (err) => {
        if (err) return res.status(500).json({erro: "Erro no banco"});
        res.json({sucesso: true});
    });
});

app.get('/aluno/minhas-atividades', verificarLogin, (req, res) => {
    db.query("SELECT * FROM atividades WHERE id_aluno = ? ORDER BY data_envio DESC", [req.session.userId], (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// --- PROFESSOR ---
app.get('/atividades/lista', verificarLogin, verificarProfessor, (req, res) => {
    // Selecionamos a coluna 'turma' da tabela usuarios e apelidamos de 'sala_aluno'
    const sql = `
        SELECT 
            atividades.*, 
            usuarios.nome AS nome_aluno, 
            usuarios.ra AS ra_aluno,
            usuarios.turma AS sala_aluno
        FROM atividades 
        JOIN usuarios ON atividades.id_aluno = usuarios.id 
        ORDER BY atividades.data_envio DESC`;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Erro ao buscar atividades:", err);
            return res.status(500).json([]);
        }
        // Retorna a lista completa; o front-end fará o filtro entre corrigidos e pendentes
        res.json(results);
    });
});

app.post('/atividades/corrigir', verificarLogin, verificarProfessor, (req, res) => {
    const { id, nota, feedback } = req.body;
    
    // Convertendo a nota para garantir que seja um número (caso venha string com vírgula)
    const notaFormatada = typeof nota === 'string' ? parseFloat(nota.replace(',', '.')) : nota;

    const sql = "UPDATE atividades SET nota = ?, feedback = ?, corrigido = TRUE WHERE id = ?";
    db.query(sql, [notaFormatada, feedback, id], (err) => {
        if (err) {
            console.error("Erro ao corrigir atividade:", err);
            return res.status(500).json({ sucesso: false, erro: "Erro ao atualizar no banco" });
        }
        res.json({ sucesso: true });
    });
});

app.listen(3000, () => console.log("Servidor rodando em http://localhost:3000"));