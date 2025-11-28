require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const prisma = new PrismaClient();

const port = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors());
app.use(express.json());

const PLAN_LIMITS = {
  TRIAL: 4000,
  ESSENTIAL: 4000,
  PROFESSIONAL: 8000
};

app.post('/tato/v2/internal/validate-usage', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ allowed: false, error: 'Token não fornecido' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) return res.status(404).json({ allowed: false, error: 'Usuário não encontrado' });

    const now = new Date();

    if (user.planType === 'TRIAL') {
      if (now > user.trialEndsAt) {
        return res.status(403).json({ 
          allowed: false, 
          error: 'Seu período de teste de 7 dias expirou. Por favor, assine um plano.' 
        });
      }
    } else {
      if (user.subscriptionStatus !== 'active') {
        return res.status(403).json({ allowed: false, error: 'Assinatura inativa ou cancelada.' });
      }
    }

    const limit = PLAN_LIMITS[user.planType];
    if (user.messagesUsed >= limit) {
      return res.status(429).json({ 
        allowed: false, 
        error: `Você atingiu o limite do plano ${user.planType} (${limit} mensagens).` 
      });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { messagesUsed: { increment: 1 } }
    });

    return res.json({ 
      allowed: true, 
      plan: user.planType, 
      usage: user.messagesUsed + 1 
    });

  } catch (error) {
    console.error("Erro na validação:", error);
    return res.status(403).json({ allowed: false, error: 'Token inválido ou expirado' });
  }
});

app.post('/tato/v2/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'Email já cadastrado.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const trialEnds = new Date();
    trialEnds.setDate(trialEnds.getDate() + 7);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash: hashedPassword,
        name,
        planType: 'TRIAL',
        trialEndsAt: trialEnds,
        messagesUsed: 0,
        subscriptionStatus: 'active'
      }
    });

    res.status(201).json({ message: 'Conta criada com sucesso!', userId: user.id });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
});

app.post('/tato/v2/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user || !user.passwordHash) {
      return res.status(400).json({ error: 'Credenciais inválidas.' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(400).json({ error: 'Credenciais inválidas.' });

    const token = jwt.sign(
      { userId: user.id, email: user.email, plan: user.planType }, 
      SECRET_KEY, 
      { expiresIn: '24h' }
    );

    res.json({ token, name: user.name, plan: user.planType });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no login.' });
  }
});

app.post('/tato/v2/auth/google', async (req, res) => {
  const { googleToken } = req.body;
  
  try {
    const ticket = await googleClient.verifyIdToken({
        idToken: googleToken,
        audience: GOOGLE_CLIENT_ID,
    });
    const { email, sub: googleId, name } = ticket.getPayload();

    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        const trialEnds = new Date();
        trialEnds.setDate(trialEnds.getDate() + 7);
        
        user = await prisma.user.create({
            data: { 
                email, 
                googleId, 
                name, 
                planType: 'TRIAL',
                trialEndsAt: trialEnds,
                subscriptionStatus: 'active'
            }
        });
    } else if (!user.googleId) {
        user = await prisma.user.update({
            where: { email },
            data: { googleId }
        });
    }

    const token = jwt.sign(
        { userId: user.id, email: user.email, plan: user.planType }, 
        SECRET_KEY, 
        { expiresIn: '24h' }
    );
    
    res.json({ token, name: user.name, plan: user.planType });

  } catch (error) {
    console.error("Erro Google Auth:", error);
    res.status(401).json({ error: 'Token Google inválido.' });
  }
});

app.get('/tato/v2/', (req, res) => {
    res.send('Auth API está rodando com segurança.');
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`Auth Server rodando localmente na porta ${port}`);
    });
}

module.exports = app;