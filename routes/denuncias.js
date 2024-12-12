const express = require('express');
const router = express.Router();
const Denuncia = require('../models/Denuncia');
const multer = require('multer');
const nodemailer = require('nodemailer'); 

// Configuração do multer para upload de arquivos
const upload = multer({
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter(req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
            return cb(new Error('Por favor, envie apenas imagens.'));
        }
        cb(null, true);
    }
});

// Configuração do Nodemailer para envio de e-mails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

// Página de registro de denúncia
router.get('/registrar', (req, res) => res.render('denuncia/registrarDenuncia'));

router.post('/registrar', upload.single('imagem'), async (req, res) => {
    const { titulo, descricao, email, localizacao, data } = req.body;
    let protocolo = Math.random().toString(36).substr(2, 9).toUpperCase();
    const imagemBase64 = req.file ? req.file.buffer.toString('base64') : null; 

    try {
        const novaDenuncia = new Denuncia({ 
            titulo, 
            descricao, 
            email, 
            localizacao, 
            data: new Date(data),
            protocolo, 
            imagem: imagemBase64 
        });
        await novaDenuncia.save();

        
        const mailOptions = {
            from: process.env.EMAIL_USER, 
            to: email, 
            subject: 'Protocolo da sua denúncia',
            text: `Sua denúncia foi registrada com sucesso! Seu número de protocolo é: ${protocolo}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Erro ao enviar o e-mail');
            }
            console.log('E-mail enviado: ' + info.response);
        });
        res.render('denuncia/protocolo', { protocolo });

    } catch (err) {
        console.error(err);
        res.status(400).send("Erro ao registrar denúncia");
    }
});



// Página para consultar denúncia
router.get('/consultar', (req, res) => res.render('denuncia/consultarDenuncia'));

// Consultar denúncia por protocolo
router.post('/consultar', async (req, res) => {
    const { protocolo } = req.body;
    let codigoMaiusculo = protocolo.toUpperCase();
    try {
         const denuncia = await Denuncia.findOne({ protocolo: codigoMaiusculo });
        if (denuncia) {
            res.render('denuncia/detalhesDenuncia', { denuncia });
        } else {
            req.flash('error', 'Denúncia não encontrada');
            res.redirect('/denuncia/consultar');     
        }
    } catch (err) {
        res.status(400).send("Erro na consulta: " + err.message);
    }
});



module.exports = router;
