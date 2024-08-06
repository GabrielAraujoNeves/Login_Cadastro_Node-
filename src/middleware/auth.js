const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    // Obtém o token do cabeçalho da requisição
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    // Verifica se o token foi fornecido
    if (!token) {
        return res.status(401).json({ error: 'Access denied, token missing!' });
    }

    try {
        // Verifica e decodifica o token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

module.exports = auth;
