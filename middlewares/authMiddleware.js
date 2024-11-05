exports.ensureAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    req.flash('error', 'Por favor, faça login para acessar esta página.');
    res.redirect('/agente/login');
};
