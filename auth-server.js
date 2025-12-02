import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

const app = express();

const prisma = global.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') global.prisma = prisma;

const port = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET;

const GOOGLE_EXTENSION_CLIENT_ID = process.env.GOOGLE_CLIENT_ID; 
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID;

const ALLOWED_GOOGLE_CLIENT_IDS = [
    GOOGLE_EXTENSION_CLIENT_ID,
    GOOGLE_WEB_CLIENT_ID
].filter(id => !!id);

const googleClient = new OAuth2Client(GOOGLE_EXTENSION_CLIENT_ID);

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const PLAN_CONFIG = {
  TRIAL: {
    name: 'Teste Gratuito',
    limit: 4000,
    price: 'Grátis',
    priceRaw: 0
  },
  ESSENTIAL: {
    name: 'Essencial',
    limit: 4000,
    price: 'R$ 19,90/mês',
    priceRaw: 19.90
  },
  PROFESSIONAL: {
    name: 'Profissional',
    limit: 6000,
    price: 'R$ 39,90/mês',
    priceRaw: 39.90
  }
};

// --- FUNÇÕES AUXILIARES ---
async function checkTrialAbuse(email, fingerprint) {
    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');

    const emailUsed = await prisma.trialLog.findUnique({ where: { emailHash } });
    if (emailUsed) return { abuse: true, reason: 'email_used', emailHash };

    if (fingerprint) {
        const deviceUsed = await prisma.trialLog.findFirst({ where: { fingerprint } });
        if (deviceUsed) return { abuse: true, reason: 'device_used', emailHash };
    }

    return { abuse: false, emailHash };
}

// --- ROTA REGISTER (CORRIGIDA) ---
app.post('/tato/v2/auth/register', async (req, res) => {
  const { email, password, name, fingerprint } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const existingUser = await prisma.user.findUnique({ 
        where: { email },
        select: { id: true }
    });
    
    if (existingUser) return res.status(400).json({ error: 'Email já cadastrado.' });

    // VERIFICAÇÃO DE ABUSO
    const { abuse, emailHash } = await checkTrialAbuse(email, fingerprint);
    
    // LÓGICA ALTERADA: Se houve abuso, não bloqueia. Apenas expira o trial.
    const trialEnds = new Date();
    if (abuse) {
        // Define data para ontem (Trial Expirado)
        trialEnds.setDate(trialEnds.getDate() - 1);
        console.log(`[Registro] Abuso detectado para ${email}. Criando conta sem trial.`);
    } else {
        // Trial normal de 7 dias
        trialEnds.setDate(trialEnds.getDate() + 7);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await prisma.$transaction(async (prisma) => {
        const user = await prisma.user.create({
            data: {
                email,
                passwordHash: hashedPassword,
                name,
                planType: 'TRIAL',
                trialEndsAt: trialEnds,
                messagesUsed: 0,
                subscriptionStatus: 'active',
                fingerprint: fingerprint || null
            },
            select: { id: true }
        });

        // Só cria log se não existir (para evitar erro de unique no emailHash)
        // Se for abuso por device mas email novo, cria o log do email novo.
        try {
            await prisma.trialLog.create({
                data: {
                    emailHash,
                    fingerprint: fingerprint || null
                }
            });
        } catch(e) { /* Ignora se já existe */ }

        return user;
    });

    res.status(201).json({ 
        message: 'Conta criada com sucesso!', 
        userId: result.id,
        warning: abuse ? 'Período de teste já utilizado anteriormente.' : null
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
});

// --- ROTA GOOGLE AUTH (CORRIGIDA) ---
app.post('/tato/v2/auth/google', async (req, res) => {
  const { googleToken, fingerprint } = req.body;
  
  if (!googleToken) return res.status(400).json({ error: 'Token do Google não fornecido.' });

  try {
    const ticket = await googleClient.verifyIdToken({
        idToken: googleToken,
        audience: ALLOWED_GOOGLE_CLIENT_IDS, 
    });

    const payload = ticket.getPayload();
    if (!payload) return res.status(401).json({ error: 'Token Google inválido.' });

    const { email, sub: googleId, email_verified, name } = payload;
    if (!email_verified) return res.status(401).json({ error: 'Email Google não verificado.' });

    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        // NOVO USUÁRIO GOOGLE
        const { abuse, emailHash } = await checkTrialAbuse(email, fingerprint);

        // LÓGICA ALTERADA: Expira o trial se houver abuso
        const trialEnds = new Date();
        if (abuse) {
            trialEnds.setDate(trialEnds.getDate() - 1);
            console.log(`[Google] Abuso detectado para ${email}. Criando conta sem trial.`);
        } else {
            trialEnds.setDate(trialEnds.getDate() + 7);
        }
        
        const userName = name || email.split('@')[0];

        user = await prisma.$transaction(async (prisma) => {
            const newUser = await prisma.user.create({
                data: { 
                    email, 
                    googleId, 
                    name: userName, 
                    planType: 'TRIAL',
                    trialEndsAt: trialEnds,
                    subscriptionStatus: 'active',
                    fingerprint: fingerprint || null
                }
            });

            try {
                await prisma.trialLog.create({
                    data: { emailHash, fingerprint: fingerprint || null }
                });
            } catch(e) { /* Ignora */ }
            
            return newUser;
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
    console.error("Erro Google Auth:", error.message);
    res.status(401).json({ error: 'Falha na autenticação com Google.' });
  }
});

// --- ROTA DELETAR CONTA ---
app.delete('/tato/v2/user/delete', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      await prisma.user.delete({ where: { id: decoded.userId } });
      res.json({ success: true, message: 'Conta deletada.' });
    } catch (error) {
      res.status(500).json({ error: 'Erro interno ao deletar conta.' });
    }
});

// --- ROTA LOGIN (Simples) ---
app.post('/tato/v2/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) return res.status(400).json({ error: 'Credenciais inválidas.' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(400).json({ error: 'Credenciais inválidas.' });

    const token = jwt.sign(
      { userId: user.id, email: user.email, plan: user.planType }, 
      SECRET_KEY, { expiresIn: '24h' }
    );
    res.json({ token, name: user.name, plan: user.planType });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno no login.' });
  }
});

// --- ROTA VALIDATE USAGE ---
app.post('/tato/v2/internal/validate-usage', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ allowed: false, error: 'Token não fornecido' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await prisma.user.findUnique({ 
        where: { id: decoded.userId },
        select: { id: true, planType: true, trialEndsAt: true, subscriptionStatus: true, messagesUsed: true }
    });

    if (!user) return res.status(404).json({ allowed: false, error: 'Usuário não encontrado' });

    const now = new Date();

    // Lógica de bloqueio: Se for trial e data expirada (trialEndsAt < now), bloqueia.
    if (user.planType === 'TRIAL') {
      if (now > user.trialEndsAt) {
        return res.status(403).json({ 
          allowed: false, 
          error: 'Seu período de teste expirou. Por favor, assine um plano.' 
        });
      }
    } else {
      if (user.subscriptionStatus !== 'active') {
        return res.status(403).json({ allowed: false, error: 'Assinatura inativa ou cancelada.' });
      }
    }

    const limit = PLAN_CONFIG[user.planType]?.limit || 4000;
    if (user.messagesUsed >= limit) {
      return res.status(429).json({ allowed: false, error: `Limite atingido.` });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { messagesUsed: { increment: 1 } }
    });

    return res.json({ allowed: true, plan: user.planType, usage: user.messagesUsed + 1 });

  } catch (error) {
    return res.status(403).json({ allowed: false, error: 'Token inválido' });
  }
});

// --- ROTA DASHBOARD ---
app.get('/tato/v2/user/dashboard', async (req, res) => {
    // Mesma lógica anterior
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await prisma.user.findUnique({ 
          where: { id: decoded.userId }
      });
      if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  
      const planDetails = PLAN_CONFIG[user.planType] || PLAN_CONFIG.TRIAL;
      let nextBilling = user.trialEndsAt;
      if (user.planType !== 'TRIAL') {
          nextBilling = new Date(); 
          nextBilling.setDate(nextBilling.getDate() + 30); 
      }
  
      const limit = planDetails.limit;
      const usage = user.messagesUsed;
      const percentage = Math.min(Math.round((usage / limit) * 100), 100);
      let displayStatus = 'Inativo';
      if (user.planType === 'TRIAL') {
          displayStatus = new Date() < new Date(user.trialEndsAt) ? 'Teste Ativo' : 'Expirado';
      } else {
          displayStatus = user.subscriptionStatus === 'active' ? 'Ativo' : 'Pendente';
      }
  
      res.json({
        subscription: { planName: planDetails.name, status: displayStatus, value: planDetails.price, nextBillingDate: nextBilling },
        usage: { used: usage, limit: limit, percentage: percentage },
        account: { email: user.email, name: user.name }
      });
    } catch (error) {
      return res.status(403).json({ error: 'Sessão inválida' });
    }
});

if (process.env.NODE_ENV !== 'production') app.listen(port, () => console.log(`API running on ${port}`));

export default app;