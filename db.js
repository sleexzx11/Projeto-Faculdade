const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',      // Usuário padrão do XAMPP
    password: '',      // Senha padrão do XAMPP (vazia)
    database: 'sistema_escolar'
});

connection.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados: ' + err.stack);
        return;
    }
    console.log('Conectado ao MySQL com sucesso!');
});

module.exports = connection;