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
    limit: 8000,
    price: 'R$ 39,90/mês',
    priceRaw: 39.90
  }
};

// --- FUNÇÕES AUXILIARES ---
async function checkTrialAbuse(email, fingerprint) {
    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');

    // Verifica por Email
    const emailUsed = await prisma.trialLog.findUnique({ where: { emailHash } });
    if (emailUsed) {
        return { 
            abuse: true, 
            reason: 'email_used', 
            emailHash, 
            usageHistory: emailUsed.usageHistory || 0 // Recupera uso anterior
        };
    }

    // Verifica por Fingerprint
    if (fingerprint) {
        const deviceUsed = await prisma.trialLog.findFirst({ where: { fingerprint } });
        if (deviceUsed) {
            return { 
                abuse: true, 
                reason: 'device_used', 
                emailHash, 
                usageHistory: deviceUsed.usageHistory || 0 // Recupera uso anterior
            };
        }
    }

    return { abuse: false, emailHash, usageHistory: 0 };
}

// --- ROTA REGISTER ---
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

    const { abuse, emailHash, usageHistory } = await checkTrialAbuse(email, fingerprint);
    
    // Define se o usuário terá trial ou não
    const trialEnds = new Date();
    if (abuse) {
        trialEnds.setDate(trialEnds.getDate() - 1); // Expira trial imediatamente
        console.log(`[Registro] Abuso detectado para ${email}. Restaurando uso: ${usageHistory}`);
    } else {
        trialEnds.setDate(trialEnds.getDate() + 7); // Trial normal
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await prisma.$transaction(async (prisma) => {
        // 1. Cria o usuário com o histórico de uso recuperado (se houver abuso)
        const user = await prisma.user.create({
            data: {
                email,
                passwordHash: hashedPassword,
                name,
                planType: 'TRIAL',
                trialEndsAt: trialEnds,
                messagesUsed: abuse ? usageHistory : 0, // Restaura o uso se for abuso
                subscriptionStatus: 'active',
                fingerprint: fingerprint || null
            },
            select: { id: true }
        });

        // 2. Garante o registro no Log de Trial
        await prisma.trialLog.upsert({
            where: { emailHash },
            update: { fingerprint: fingerprint || null }, // Atualiza fingerprint se mudou
            create: {
                emailHash,
                fingerprint: fingerprint || null,
                usageHistory: 0 // Inicia log com 0
            }
        });

        return user;
    });

    res.status(201).json({ 
        message: 'Conta criada com sucesso!', 
        userId: result.id,
        warning: abuse ? 'Período de teste já utilizado anteriormente.' : null
    });

  } catch (error) {
    console.error("Erro Registro:", error);
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
});

// --- ROTA GOOGLE AUTH ---
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
        const { abuse, emailHash, usageHistory } = await checkTrialAbuse(email, fingerprint);

        const trialEnds = new Date();
        if (abuse) {
            trialEnds.setDate(trialEnds.getDate() - 1);
            console.log(`[Google] Abuso detectado para ${email}. Restaurando uso: ${usageHistory}`);
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
                    fingerprint: fingerprint || null,
                    messagesUsed: abuse ? usageHistory : 0 // Restaura uso se abuso
                }
            });

            await prisma.trialLog.upsert({
                where: { emailHash },
                update: { fingerprint: fingerprint || null }, 
                create: { emailHash, fingerprint: fingerprint || null, usageHistory: 0 }
            });
            
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
    
    res.json({ 
        token, 
        name: user.name, 
        plan: user.planType,
        warning: (user.createdAt > new Date(Date.now() - 10000) && user.trialEndsAt < new Date()) 
                 ? 'Período de teste já utilizado anteriormente.' 
                 : null
    });

  } catch (error) {
    console.error("Erro Google Auth:", error.message);
    res.status(401).json({ error: 'Falha na autenticação com Google.' });
  }
});

// --- ROTA DELETAR CONTA (ATUALIZADA) ---
app.delete('/tato/v2/user/delete', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
      
      if (user) {
          // Salva o uso atual no log permanente antes de deletar
          const emailHash = crypto.createHash('sha256').update(user.email.toLowerCase().trim()).digest('hex');
          
          await prisma.trialLog.upsert({
              where: { emailHash },
              update: { usageHistory: user.messagesUsed }, // Salva o quanto usou até agora
              create: { 
                  emailHash, 
                  fingerprint: user.fingerprint, 
                  usageHistory: user.messagesUsed 
              }
          });

          await prisma.user.delete({ where: { id: decoded.userId } });
          res.json({ success: true, message: 'Conta deletada.' });
      } else {
          res.status(404).json({ error: 'Usuário não encontrado.' });
      }

    } catch (error) {
      console.error("Erro delete:", error);
      res.status(500).json({ error: 'Erro interno ao deletar conta.' });
    }
});

// --- ROTA LOGIN ---
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

// --- ROTA DASHBOARD ---
app.get('/tato/v2/user/dashboard', async (req, res) => {
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

// --- ROTA VALIDATE USAGE (BLOQUEIO) ---
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

    // 1. BLOQUEIO DE TEMPO (TRIAL)
    // Se for Trial e a data de hoje for maior que trialEndsAt, bloqueia.
    // Como abusadores tem trialEndsAt setado para o passado, eles caem aqui.
    if (user.planType === 'TRIAL') {
      if (now > user.trialEndsAt) {
        return res.status(403).json({ 
          allowed: false, 
          error: 'Seu período de teste expirou. Por favor, assine um plano.' 
        });
      }
    } else {
      // Bloqueio de Assinatura Inativa
      if (user.subscriptionStatus !== 'active') {
        return res.status(403).json({ allowed: false, error: 'Assinatura inativa ou cancelada.' });
      }
    }

    // 2. BLOQUEIO DE LIMITE (MENSAGENS)
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

if (process.env.NODE_ENV !== 'production') app.listen(port, () => console.log(`API running on ${port}`));

export default app;