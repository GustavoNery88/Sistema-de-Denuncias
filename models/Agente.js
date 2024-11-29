const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const AgenteSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    cpf: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
    resetToken: { type: String, default: null },
    resetTokenExpiration: { type: Date, default: null },
    admin: {type: Boolean, default: false}
});

// Hash de senha antes de salvar
AgenteSchema.pre('save', async function(next) {
    const salt = await bcrypt.genSalt(10);
    this.senha = await bcrypt.hash(this.senha, salt);
    next();
});

module.exports = mongoose.model('Agente', AgenteSchema);
