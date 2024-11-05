const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const Agente = require('../models/Agente');
const Denuncia = require('../models/Denuncia');
const { ensureAuthenticated } = require('../middlewares/authMiddleware');

// Página de cadastro de agente
router.get('/cadastrar', ensureAuthenticated, (req, res) => res.render('agente/cadastrarAgente'));

// Processa o cadastro do agente
router.post('/cadastrar', ensureAuthenticated, async (req, res) => {
    const { nome, cpf, email, senha, admin } = req.body;
    const cpfFormatado = cpf.replace(/\D/g, '');

    try {
        // Cria um novo agente

        // Checa se o CPF já está cadastrado
        const agenteJaExistente = await Agente.findOne({ cpf: cpfFormatado });
        const emailJaExistente = await Agente.findOne({ email: email });

        if (agenteJaExistente) {
            req.flash('error', 'Este CPF já está cadastrado!');
            return res.redirect('/agente/cadastrar');
        }

        else if (emailJaExistente) {
            req.flash('error', 'Este e-mail já está cadastrado!');
            return res.redirect('/agente/cadastrar');
        }

        else if (senha.length < 8) {
            req.flash('error', 'A senha deve ter pelo menos 8 caracteres ou mais!');
            return res.redirect('/agente/cadastrar');
        }

        else if (cpfFormatado.length != 11) {
            req.flash('error', 'CPF invalido!');
            return res.redirect('/agente/cadastrar');
        }

        const novoAgente = new Agente({
            nome,
            cpf: cpfFormatado,
            email,
            senha,
            admin: admin === 'on' // Checkbox do campo admin
        });

        await novoAgente.save(); // Salva o agente no banco de dados

        req.flash('success', 'Agente cadastrado com sucesso!');
        res.redirect('/agente/cadastrar');

    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao cadastrar agente. Tente novamente.');
        res.redirect('/agente/cadastrar');
    }
});


// Rota para exibir todas as denúncias novas (Recebidas)
router.get('/novasDenuncias', ensureAuthenticated, async (req, res) => {
    try {
        const denunciasNovas = await Denuncia.find({ status: 'Recebida' }); // Filtra denúncias pelo status
        res.render('agente/novasDenuncias', { denuncias: denunciasNovas }); // Renderiza a view com as denúncias
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao buscar denúncias.');
        res.redirect('/'); // Redireciona em caso de erro
    }
});

// Rota para visualizar detalhes da denúncia
router.get('/visualizar/:id', async (req, res) => {
    const denunciaId = req.params.id;

    try {
        // Busca a denúncia pelo ID para visualização
        const denuncia = await Denuncia.findById(denunciaId);
        if (!denuncia) {
            req.flash('error', 'Denúncia não encontrada.');
            return res.redirect('/agente/novasDenuncias');
        }

        res.render('agente/detalhesDenuncia', { denuncia });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao visualizar a denúncia.');
        res.redirect('/agente/novasDenuncias');
    }
});

// Rota para se atribuir a uma denúncia
router.get('/atribuir/:id', async (req, res) => {
    const denunciaId = req.params.id;

    try {
        // Atribui o agente à denúncia atualizando o campo responsável
        await Denuncia.findByIdAndUpdate(denunciaId, { status: 'Em andamento' });

        req.flash('success', 'Você se atribuiu a esta denúncia com sucesso.');
        res.redirect('/agente/novasDenuncias'); // Redireciona para a página de novas denúncias
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao atribuir-se à denúncia.');
        res.redirect('/agente/novasDenuncias');
    }
});


// Página de Login
router.get('/login', (req, res) => res.render('agente/login'));

router.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;

    try {
        // Busca o agente pelo CPF
        const agente = await Agente.findOne({ cpf });
        if (!agente) {
            req.flash('error', 'CPF não encontrado!');
            return res.redirect('/agente/login');
        }

        // Verifica se a senha está correta
        const isMatch = await bcrypt.compare(senha, agente.senha);
        if (!isMatch) {
            req.flash('error', 'Senha incorreta');
            return res.redirect('/agente/login');
        }

        // Salva o agente na sessão
        req.session.user = {
            id: agente._id,
            nome: agente.nome,
            admin: agente.admin
        };

        req.flash('success', 'Usuário logado com sucesso!');
        res.redirect('/agente/novasDenuncias');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao processar o login!');
        res.redirect('/agente/login');
    }
});


router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return console.error(err);
        res.redirect('/agente/login');
    });
    
});

module.exports = router;

