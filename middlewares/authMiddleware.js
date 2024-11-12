const jwt = require('jsonwebtoken');

const ensureAuthenticatedJWT = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        req.flash('error', 'Você precisa estar logado para acessar essa página.');
        return res.redirect('/agente/login');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Anexa os dados do usuário à requisição
        res.locals.user = decoded; // Disponibiliza na view
        next();
    } catch (err) {
        console.error(err);
        req.flash('error', 'Token inválido ou expirado. Por favor, faça login novamente.');
        res.redirect('/agente/login');
    }
};

// Verificação de admin
function ensureAdmin(req, res, next) {
    if (req.user && req.user.admin) {
        return next();
    }
    req.flash('error', 'Acesso negado: apenas administradores podem acessar esta página.');
    res.redirect('/'); // Redireciona para a página inicial ou para uma página de acesso negado
}

module.exports = { ensureAuthenticatedJWT, ensureAdmin };

