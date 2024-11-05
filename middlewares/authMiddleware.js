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

module.exports = { ensureAuthenticatedJWT };
