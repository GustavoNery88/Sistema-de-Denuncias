const mongoose = require('mongoose');

const DenunciaSchema = new mongoose.Schema({
    titulo: { type: String, required: true },
    descricao: { type: String, required: true },
    email: { type: String, required: true },
    localizacao: { type: String, required: true },
    data: { type: Date, required: true },
    status: { type: String, default: 'Recebida' },
    protocolo: { type: String, unique: true },
    imagem: { type: String },  // Armazenar imagem em base64
    agenteAtribuido: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Agente' // Referência ao modelo 'Agente'
    }
});

module.exports = mongoose.model('Denuncia', DenunciaSchema);
