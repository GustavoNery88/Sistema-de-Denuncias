const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const { create } = require('express-handlebars');
const session = require('express-session');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser'); // Adicione esta linha

const app = express();

// Configurar Handlebars como motor de templates com opções de controle de protótipo
const hbs = create({
    defaultLayout: 'main',
    helpers: {},  // Caso precise de helpers personalizados
    runtimeOptions: {
        allowProtoPropertiesByDefault: true,  // Permitir acesso a propriedades de protótipos
        allowProtoMethodsByDefault: true      // Permitir acesso a métodos de protótipos, caso necessário
    },
    helpers: {
        formatDate: function (date) {
            if (!date) return '';
            const d = new Date(date);
            return `${('0' + d.getDate()).slice(-2)}/${('0' + (d.getMonth() + 1)).slice(-2)}/${d.getFullYear()}`;
        },
        
    }
});


app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

// Middleware para manipular cookies
app.use(cookieParser());

// Configurações de sessão e flash para mensagens
app.use(session({
    secret: 'Sdenucias',
    resave: false,
    saveUninitialized: true
}));

// Middleware do connect-flash
app.use(flash());

// Middleware para passar mensagens flash para as views
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success');
    res.locals.error_msg = req.flash('error');
    next();
});


app.use((req, res, next) => { 
    res.locals.user = null; // Não vamos usar sessão para usuário
    res.locals.isAuthenticated = req.cookies.token !== undefined; // Verifica se o token está definido
    next();
});


// Conectar ao MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB conectado'))
    .catch(err => console.log(err));

// Configurações
app.set('view engine', 'handlebars');
app.use(express.urlencoded({ extended: false }));

// Servir arquivos estáticos
app.use(express.static('public'));

// Rotas
const denunciaRoutes = require('./routes/denuncias.js');
app.use('/denuncia', denunciaRoutes); 

const agenteRoutes = require('./routes/agentes.js');
app.use('/agente', agenteRoutes);

// Rota para a página inicial
app.get('/', (req, res) => {
    res.render('denuncia/home'); // Não precisa passar isAuthenticated, já está em res.locals
});

// Inicializar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));


