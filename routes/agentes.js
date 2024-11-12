const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // Adicione esta linha
const router = express.Router();
const Agente = require('../models/Agente');
const Denuncia = require('../models/Denuncia');
const { ensureAuthenticatedJWT } = require('../middlewares/authMiddleware'); // Atualize para middleware JWT


// Página de cadastro de agente
router.get('/cadastrar', ensureAuthenticatedJWT, (req, res) => res.render('agente/cadastrarAgente'));

// Processa o cadastro do agente
router.post('/cadastrar', ensureAuthenticatedJWT, async (req, res) => {
    const { nome, cpf, email, senha, admin } = req.body;
    const cpfFormatado = cpf.replace(/\D/g, '');

    try {
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
            req.flash('error', 'CPF inválido!');
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
router.get('/novasDenuncias', ensureAuthenticatedJWT, async (req, res) => {
    try {
        const denunciasNovas = await Denuncia.find({ status: 'Recebida' }); // Filtra denúncias pelo status
        res.render('agente/novasDenuncias', { denuncias: denunciasNovas, user: req.user }); // Passa o usuário para a view
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao buscar denúncias.');
        res.redirect('/'); // Redireciona em caso de erro
    }
});

// Rota para visualizar detalhes da denúncia
router.get('/visualizar/:id', ensureAuthenticatedJWT, async (req, res) => {
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

// Rota para editar detalhes da denúncia
router.get('/editarDenuncia/:id', ensureAuthenticatedJWT, async (req, res) => {
    const denunciaId = req.params.id;

    try {
        // Busca a denúncia pelo ID para visualização
        const denuncia = await Denuncia.findById(denunciaId);
        if (!denuncia) {
            req.flash('error', 'Denúncia não encontrada.');
            return res.redirect('/agente/novasDenuncias');
        }

        res.render('agente/editarDenuncia', { denuncia });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao visualizar a denúncia.');
        res.redirect('/agente/novasDenuncias');
    }
});



// Rota para se atribuir da denúncia
router.post('/atribuir/:id', ensureAuthenticatedJWT, async (req, res) => {
    const denunciaId = req.params.id;
    const agenteId = req.user.id; // ID do agente logado

    try {
        // Atualiza a denúncia com o ID do agente e muda o status para 'Em análise'
        await Denuncia.findByIdAndUpdate(denunciaId, {
            agenteAtribuido: agenteId,
            status: 'Em análise'
        });

        req.flash('success', 'Você se atribuiu a esta denúncia com sucesso.');
        res.redirect('/agente/novasDenuncias'); // Redireciona para a página de novas denúncias
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao atribuir-se à denúncia.');
        res.redirect('/agente/novasDenuncias');
    }
});

// Rota para editar o status da denúncia
router.post('/editarDenuncia', ensureAuthenticatedJWT, async (req, res) => {
    const { id, status } = req.body;

    try {
        // Atualiza a denúncia com o novo status
        await Denuncia.findByIdAndUpdate(id, { status });

        req.flash('success', 'Status da denúncia atualizado com sucesso!');
        res.redirect('/agente/denunciasAtribuidas');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao atualizar o status da denúncia.');
        res.redirect('/agente/denunciasAtribuidas');
    }
});


// Rota para exibir denúncias atribuídas ao agente logado
router.get('/denunciasAtribuidas', ensureAuthenticatedJWT, async (req, res) => {
    try {
        const denunciasAtribuidas = await Denuncia.find({ agenteAtribuido: req.user.id });

        // Busca o agente pelo ID
        const agente = await Agente.findById(req.user.id);

        res.render('agente/denunciasAtribuidas', {
            denuncias: denunciasAtribuidas,
            agente
        });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao buscar denúncias atribuídas.');
        res.redirect('/agente/novasDenuncias');
    }
});


// Rota para se desatribuir da denúncia
router.post('/desatribuir/:id', ensureAuthenticatedJWT, async (req, res) => {
    const denunciaId = req.params.id;

    try {
        await Denuncia.findByIdAndUpdate(denunciaId, {
            agenteAtribuido: null,
            status: 'Recebida' // Retorna o status para "Recebida"
        });

        req.flash('success', 'Você se desatribuiu desta denúncia com sucesso.');
        res.redirect('/agente/denunciasAtribuidas');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao desatribuir-se da denúncia.');
        res.redirect('/agente/denunciasAtribuidas');
    }
});

// Rota para exibir os usuários cadastrados
router.get('/usuarios', ensureAuthenticatedJWT, async (req, res) => {
    try {
        const usuarios = await Agente.find({}, 'nome cpf email'); // Inclua email caso precise exibir essa informação
        res.render('agente/usuarios', { usuarios, user: req.user }); // Renderiza a view e passa os agentes como dados
    } catch (error) {
        console.error(error);
        req.flash("error", "Erro ao buscar os usuários.");
        res.redirect('/');
    }
});


// Rota para visualizar o usuario
router.get('/usuarioVisualizar/:id', ensureAuthenticatedJWT, async (req, res) => {
    const usuarioId = req.params.id;

    try {
        // Busca o agente pelo ID e exclui o campo 'senha' dos dados retornados
        const usuario = await Agente.findById(usuarioId).select('nome cpf email');
        if (!usuario) {
            req.flash('error', 'Usuário não encontrado.');
            return res.redirect('/agente/usuarios');
        }

        res.render('agente/visualizarUsuario', { usuario });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao visualizar o usuário.');
        res.redirect('/agente/usuarios');
    }
});

// Rota para exibir o formulário de edição do usuário
router.get('/usuarioEditar/:id', ensureAuthenticatedJWT, async (req, res) => {
    const usuarioId = req.params.id;

    try {
        const usuario = await Agente.findById(usuarioId).select('nome cpf email');
        if (!usuario) {
            req.flash('error', 'Usuário não encontrado.');
            return res.redirect('/agente/usuarios');
        }

        res.render('agente/editarUsuario', { usuario });
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao carregar o usuário para edição.');
        res.redirect('/agente/usuarios');
    }
});

// Rota para processar a edição do usuário
router.post('/usuarioEditar/:id', ensureAuthenticatedJWT, async (req, res) => {
    const usuarioId = req.params.id;
    const { nome, cpf, email } = req.body;

    try {
        await Agente.findByIdAndUpdate(usuarioId, { nome, cpf, email });
        req.flash('success', 'Usuário atualizado com sucesso!');
        res.redirect('/agente/usuarios');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao atualizar o usuário.');
        res.redirect(`/agente/usuarioEditar/${usuarioId}`);
    }
});

// Rota para excluir o usuário
router.get('/usuarioExcluir/:id', ensureAuthenticatedJWT, async (req, res) => {
    const usuarioId = req.params.id;

    try {
        await Agente.findByIdAndDelete(usuarioId);
        req.flash('success', 'Usuário excluído com sucesso!');
        res.redirect('/agente/usuarios');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao excluir o usuário.');
        res.redirect('/agente/usuarios');
    }
});



// Página de Login
router.get('/login', (req, res) => res.render('agente/login'));


// Exemplo na rota de login
router.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;

    try {
        // Busca o agente pelo CPF
        const agente = await Agente.findOne({ cpf, });
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

        // Gera o JWT
        const payload = {
            id: agente._id,
            nome: agente.nome,
            admin: agente.admin
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION });

        // Define o token como um cookie HTTP-only
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        req.flash('success', 'Usuário logado com sucesso!');
        res.redirect('/agente/novasDenuncias');
    } catch (error) {
        console.error(error);
        req.flash('error', 'Erro ao processar o login!');
        res.redirect('/agente/login');
    }
});

// Rota para Logout
router.get('/logout', (req, res) => {
    // Remove o cookie do token
    res.clearCookie('token');
    req.flash('success', 'Saiu!');
    res.redirect('/agente/login');
});


module.exports = router;


