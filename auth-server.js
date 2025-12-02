import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';

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

// --- CONFIGURAÇÃO DOS PLANOS (Adaptado para o Dashboard) ---
// Esses dados alimentam tanto a validação quanto a interface visual
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

// --- ROTA DE DASHBOARD (NOVA) ---
// Retorna todos os dados para montar a tela da imagem (Assinatura, Uso, Conta)
app.get('/tato/v2/user/dashboard', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      
      // Busca dados completos do usuário
      // NOTA: Adicione 'nextBillingDate' ao seu schema.prisma se não existir, 
      // ou usaremos trialEndsAt como fallback.
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
              // nextBillingDate: true // Descomente se tiver esse campo no banco
          }
      });
  
      if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
  
      const planDetails = PLAN_CONFIG[user.planType] || PLAN_CONFIG.TRIAL;
      
      // Lógica de Data de Cobrança
      // Se for Trial, a "próxima cobrança" é o fim do trial.
      // Se for Assinatura, seria a data de renovação (mockamos +30 dias se não tiver no banco)
      let nextBilling = user.trialEndsAt;
      if (user.planType !== 'TRIAL') {
          // Exemplo: user.nextBillingDate || new Date(Date.now() + 30*24*60*60*1000)
          nextBilling = new Date(); 
          nextBilling.setDate(nextBilling.getDate() + 30); 
      }
  
      // Cálculo de Porcentagem
      const limit = planDetails.limit;
      const usage = user.messagesUsed;
      const percentage = Math.min(Math.round((usage / limit) * 100), 100);
  
      // Formata Status para exibição
      let displayStatus = 'Inativo';
      if (user.planType === 'TRIAL') {
          displayStatus = new Date() < new Date(user.trialEndsAt) ? 'Teste Ativo' : 'Expirado';
      } else {
          displayStatus = user.subscriptionStatus === 'active' ? 'Ativo' : 'Pendente';
      }
  
      // Resposta estruturada para o Frontend
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
      console.error(error);
      return res.status(403).json({ error: 'Sessão inválida' });
    }
});

// --- ROTA VALIDATE USAGE (Mantida para a extensão) ---
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

    // Usa a nova configuração centralizada
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

// ... (Rota register permanece igual) ...
app.post('/tato/v2/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  try {
    const existingUser = await prisma.user.findUnique({ 
        where: { email },
        select: { id: true }
    });
    
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
      },
      select: { id: true }
    });

    res.status(201).json({ message: 'Conta criada com sucesso!', userId: user.id });

  } catch (error) {
    res.status(500).json({ error: 'Erro interno ao criar conta.' });
  }
});

// ... (Rota login permanece igual) ...
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

// --- ROTA GOOGLE AUTH (Suporte Multi-Client) ---
app.post('/tato/v2/auth/google', async (req, res) => {
  const { googleToken } = req.body;
  
  if (!googleToken) {
      return res.status(400).json({ error: 'Token do Google não fornecido.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
        idToken: googleToken,
        audience: ALLOWED_GOOGLE_CLIENT_IDS, 
    });

    const payload = ticket.getPayload();
    
    if (!payload) {
        return res.status(401).json({ error: 'Token Google inválido.' });
    }

    const { email, sub: googleId, email_verified, name, picture } = payload;

    if (!email_verified) {
        return res.status(401).json({ error: 'Email Google não verificado.' });
    }

    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        const trialEnds = new Date();
        trialEnds.setDate(trialEnds.getDate() + 7);
        
        const userName = name || email.split('@')[0];

        user = await prisma.user.create({
            data: { 
                email, 
                googleId, 
                name: userName, 
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
    console.error("Erro Google Auth:", error.message);
    res.status(401).json({ error: 'Falha na autenticação com Google. Origem não autorizada.' });
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
