import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto'; // Necessário para gerar hash do email

const app = express();

const prisma = global.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') global.prisma = prisma;

const port = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET;

// --- CONFIGURAÇÃO DE MÚLTIPLOS CLIENT IDS ---
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

// --- CONFIGURAÇÃO DOS PLANOS ---
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

// --- FUNÇÃO AUXILIAR: VERIFICAÇÃO DE ABUSO DE TRIAL ---
async function checkTrialAbuse(email, fingerprint) {
    // 1. Gera um hash do email para comparar anonimamente
    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');

    // 2. Verifica se o Email já usou trial antes (mesmo se deletou a conta)
    const emailUsed = await prisma.trialLog.findUnique({
        where: { emailHash }
    });

    if (emailUsed) return { abuse: true, reason: 'email_used' };

    // 3. Verifica se o Dispositivo (Fingerprint) já usou trial antes
    if (fingerprint) {
        const deviceUsed = await prisma.trialLog.findFirst({
            where: { fingerprint }
        });
        if (deviceUsed) return { abuse: true, reason: 'device_used' };
    }

    return { abuse: false, emailHash };
}

// --- FUNÇÃO AUXILIAR: REGISTRAR USO DE TRIAL ---
async function registerTrialUsage(emailHash, fingerprint) {
    try {
        await prisma.trialLog.create({
            data: {
                emailHash,
                fingerprint
            }
        });
    } catch (e) {
        // Ignora erro se já existir (race condition)
        console.log("Log de trial já existente ou erro:", e.message);
    }
}


// --- ROTA DE DASHBOARD ---
app.get('/tato/v2/user/dashboard', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      const user = await prisma.user.findUnique({ 
          where: { id: decoded.userId },
          select: {
              id: true,
              email: true,
              name: true,
              planType: true,
              trialEndsAt: true,
              subscriptionStatus: true,
              messagesUsed: true,
          }
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
        subscription: {
          planName: planDetails.name,
          status: displayStatus,
          value: planDetails.price,
          nextBillingDate: nextBilling
        },
        usage: {
          used: usage,
          limit: limit,
          percentage: percentage
        },
        account: {
          email: user.email,
          name: user.name
        }
      });
  
    } catch (error) {
      return res.status(403).json({ error: 'Sessão inválida' });
    }
});

// --- ROTA DELETAR CONTA ---
app.delete('/tato/v2/user/delete', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      // O registro na tabela 'TrialLog' NÃO é deletado aqui.
      // Isso garante que se ele tentar criar conta de novo com mesmo email, saberemos.
      
      await prisma.user.delete({ 
          where: { id: decoded.userId } 
      });
  
      res.json({ success: true, message: 'Conta deletada. Histórico de uso mantido anonimamente.' });
  
    } catch (error) {
      if (error.code === 'P2025') {
          return res.status(404).json({ error: 'Usuário não encontrado.' });
      }
      console.error("Erro ao deletar conta:", error);
      return res.status(500).json({ error: 'Erro interno ao deletar conta.' });
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
        select: {
            id: true,
            planType: true,
            trialEndsAt: true,
            subscriptionStatus: true,
            messagesUsed: true
        }
    });

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

    const limit = PLAN_CONFIG[user.planType]?.limit || 4000;
    
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
    return res.status(403).json({ allowed: false, error: 'Token inválido ou expirado' });
  }
});

// --- ROTA REGISTER (ATUALIZADA COM PROTEÇÃO) ---
app.post('/tato/v2/auth/register', async (req, res) => {
  const { email, password, name, fingerprint } = req.body; // Aceita fingerprint do front

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    // 1. Verifica existência na tabela de usuários ativos
    const existingUser = await prisma.user.findUnique({ 
        where: { email },
        select: { id: true }
    });
    
    if (existingUser) return res.status(400).json({ error: 'Email já cadastrado.' });

    // 2. VERIFICAÇÃO DE ABUSO DE TRIAL
    const { abuse, emailHash } = await checkTrialAbuse(email, fingerprint);
    
    if (abuse) {
        return res.status(403).json({ 
            error: 'Este dispositivo ou e-mail já utilizou o período de teste gratuito anteriormente.' 
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const trialEnds = new Date();
    trialEnds.setDate(trialEnds.getDate() + 7);

    // 3. Cria Usuário e Registra Log de Trial
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

        await prisma.trialLog.create({
            data: {
                emailHash,
                fingerprint: fingerprint || null
            }
        });

        return user;
    });

    res.status(201).json({ message: 'Conta criada com sucesso!', userId: result.id });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
});

// --- ROTA LOGIN ---
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
    res.status(500).json({ error: 'Erro interno no login.' });
  }
});

// --- ROTA GOOGLE AUTH (ATUALIZADA COM PROTEÇÃO) ---
app.post('/tato/v2/auth/google', async (req, res) => {
  const { googleToken, fingerprint } = req.body; // Aceita fingerprint do front
  
  if (!googleToken) {
      return res.status(400).json({ error: 'Token do Google não fornecido.' });
  }

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

    // SE O USUÁRIO NÃO EXISTE, VAMOS CRIAR (VERIFICAR ABUSO ANTES)
    if (!user) {
        // 1. VERIFICAÇÃO DE ABUSO DE TRIAL
        const { abuse, emailHash } = await checkTrialAbuse(email, fingerprint);

        // Se houve abuso, não criamos a conta ou criamos bloqueada? 
        // Idealmente bloqueamos o registro para forçar contato ou login com conta antiga.
        if (abuse) {
            return res.status(403).json({ 
                error: 'Este dispositivo ou e-mail já utilizou o período de teste gratuito anteriormente.' 
            });
        }

        const trialEnds = new Date();
        trialEnds.setDate(trialEnds.getDate() + 7);
        const userName = name || email.split('@')[0];

        // 2. Cria Usuário e Registra Log de Trial
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

            await prisma.trialLog.create({
                data: {
                    emailHash,
                    fingerprint: fingerprint || null
                }
            });
            return newUser;
        });

    } else if (!user.googleId) {
        // Vincula a conta existente ao Google
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
    // Se o erro for do nosso bloqueio de abuso (403), repassa o status
    if (error.message.includes('teste gratuito')) {
        return res.status(403).json({ error: 'Este dispositivo já utilizou o teste gratuito.' });
    }
    res.status(401).json({ error: 'Falha na autenticação com Google.' });
  }
});

app.get('/tato/v2/', (req, res) => {
    res.send('Auth API (ESM Optimized) está rodando com segurança.');
});

if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`Auth Server rodando localmente na porta ${port}`);
        console.log(`Google Clients Permitidos:`, ALLOWED_GOOGLE_CLIENT_IDS);
    });
}

export default app;