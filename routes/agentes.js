const express = require('express');
const router = express.Router();
const Agente = require('../models/Agente'); // Importa o modelo de Agente

// Página de cadastro de agente
router.get('/cadastrar', (req, res) => res.render('agente/cadastrarAgente'));

// Processa o cadastro do agente
router.post('/cadastrar', async (req, res) => {
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

        else if(emailJaExistente){
            req.flash('error', 'Este e-mail já está cadastrado!');
            return res.redirect('/agente/cadastrar');
        }

        else if(senha.length < 8){
            req.flash('error', 'A senha deve ter pelo menos 8 caracteres ou mais!');
            return res.redirect('/agente/cadastrar');
        }

        else if(cpfFormatado.length != 11){
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

module.exports = router;
