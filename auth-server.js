import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import Stripe from 'stripe'; // Integração Stripe

const app = express();

const prisma = global.prisma || new PrismaClient();
if (process.env.NODE_ENV !== 'production') global.prisma = prisma;

const port = process.env.PORT || 4000;
const SECRET_KEY = process.env.JWT_SECRET;

// Configuração Stripe
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const stripe = new Stripe(STRIPE_SECRET_KEY);

const GOOGLE_EXTENSION_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_WEB_CLIENT_ID = process.env.GOOGLE_WEB_CLIENT_ID;

const ALLOWED_GOOGLE_CLIENT_IDS = [
    GOOGLE_EXTENSION_CLIENT_ID,
    GOOGLE_WEB_CLIENT_ID
].filter(id => !!id);

const googleClient = new OAuth2Client(GOOGLE_EXTENSION_CLIENT_ID);

// --- 1. ROTA DE WEBHOOK STRIPE (IMPORTANTE: Antes dos middlewares globais) ---
app.post('/tato/v2/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error(`Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
        switch (event.type) {
            case 'checkout.session.completed': {
                const session = event.data.object;

                // Tenta pegar o ID de várias formas: Metadata, Client Reference ou busca por Email
                let userId = session.metadata?.userId || session.client_reference_id;
                const subscriptionId = session.subscription;
                const customerId = session.customer;
                const customerEmail = session.customer_details?.email || session.email;

                // Se não veio ID direto, tenta achar o usuário pelo e-mail do checkout
                if (!userId && customerEmail) {
                    const userByEmail = await prisma.user.findUnique({ where: { email: customerEmail } });
                    if (userByEmail) userId = userByEmail.id;
                }

                if (!userId) {
                    console.error("Webhook: User ID não encontrado (nem por ID, nem por email).");
                    break;
                }

                // --- CORREÇÃO ROBUSTA PARA DETECÇÃO DE PLANO (TRIAL & LINKS DIRETOS) ---
                let planType = session.metadata?.planType;

                // Se não veio no metadata (link direto), consultamos a assinatura expandindo o produto
                if (!planType && subscriptionId) {
                    try {
                        // Expande 'product' para podermos checar o NOME do plano
                        const subscription = await stripe.subscriptions.retrieve(subscriptionId, {
                            expand: ['items.data.price.product']
                        });

                        const priceItem = subscription.items.data[0]?.price;
                        const product = priceItem?.product; // Objeto produto expandido
                        const priceAmount = priceItem?.unit_amount; // Preço recorrente real (ex: 3990)

                        // 1. Prioridade: Verifica pelo NOME do produto (mais seguro para Trials)
                        if (product && product.name) {
                            const name = product.name.toLowerCase();
                            if (name.includes('profissional') || name.includes('professional')) {
                                planType = 'PROFESSIONAL';
                            } else if (name.includes('essencial') || name.includes('essential')) {
                                planType = 'ESSENTIAL';
                            }
                        }

                        // 2. Fallback: Verifica pelo PREÇO recorrente (ignora se o pagto de hoje foi 0)
                        if (!planType && priceAmount) {
                            if (priceAmount >= 3900) {
                                planType = 'PROFESSIONAL';
                            } else {
                                planType = 'ESSENTIAL';
                            }
                        }

                        console.log(`[Webhook] Assinatura analisada. Produto: "${product?.name}", Preço: ${priceAmount}, Plano Definido: ${planType}`);

                    } catch (subError) {
                        console.error("[Webhook] Erro ao buscar detalhe da assinatura:", subError);
                    }
                }

                // 3. Último recurso: Valor pago na sessão (falha em trials gratuitos, pois amount=0)
                if (!planType) {
                    planType = session.amount_total >= 3900 ? 'PROFESSIONAL' : 'ESSENTIAL';
                    console.log(`[Webhook] Fallback para valor pago na sessão (pode ser impreciso em trials): ${planType}`);
                }

                await prisma.user.update({
                    where: { id: userId },
                    data: {
                        subscriptionStatus: 'active',
                        planType: planType,
                        stripeCustomerId: customerId,
                        stripeSubscriptionId: subscriptionId,
                        nextBillingDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
                    }
                });
                console.log(`[Stripe] Assinatura ativada para usuário ${userId}. Plano Final: ${planType}`);
                break;
            }

            case 'invoice.payment_failed': {
                const invoice = event.data.object;
                const customerId = invoice.customer;

                const user = await prisma.user.findFirst({ where: { stripeCustomerId: customerId } });
                if (user) {
                    await prisma.user.update({
                        where: { id: user.id },
                        data: { subscriptionStatus: 'past_due' }
                    });
                    console.log(`[Stripe] Pagamento falhou para ${user.email}`);
                }
                break;
            }

            case 'customer.subscription.deleted': {
                const subscription = event.data.object;
                const customerId = subscription.customer;

                const user = await prisma.user.findFirst({ where: { stripeCustomerId: customerId } });
                if (user) {
                    await prisma.user.update({
                        where: { id: user.id },
                        data: {
                            subscriptionStatus: 'canceled',
                            planType: 'TRIAL',
                        }
                    });
                    console.log(`[Stripe] Assinatura cancelada para ${user.email}`);
                }
                break;
            }
        }
    } catch (error) {
        console.error("Erro processando webhook:", error);
        return res.json({ received: true, status: 'error_processing' });
    }

    res.json({ received: true });
});

// --- 2. MIDDLEWARES GLOBAIS ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const PLAN_CONFIG = {
    TRIAL: {
        name: 'Teste Gratuito',
        limit: 2000,
        price: 'Grátis',
        priceRaw: 0
    },
    ESSENTIAL: {
        name: 'Essencial',
        limit: 2000,
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

// --- FUNÇÕES AUXILIARES (PROTEÇÃO DE TRIAL) ---
async function checkTrialAbuse(email, fingerprint) {
    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');

    const emailUsed = await prisma.trialLog.findUnique({ where: { emailHash } });
    if (emailUsed) {
        return {
            abuse: true,
            reason: 'email_used',
            emailHash,
            usageHistory: emailUsed.usageHistory || 0
        };
    }

    if (fingerprint) {
        const deviceUsed = await prisma.trialLog.findFirst({ where: { fingerprint } });
        if (deviceUsed) {
            return {
                abuse: true,
                reason: 'device_used',
                emailHash,
                usageHistory: deviceUsed.usageHistory || 0
            };
        }
    }

    return { abuse: false, emailHash, usageHistory: 0 };
}

// --- ROTAS DE PAGAMENTO (STRIPE) ---

app.post('/tato/v2/payment/create-checkout', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const { priceId, planType } = req.body;

        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        let customerId = user.stripeCustomerId;

        if (!customerId) {
            const customer = await stripe.customers.create({
                email: user.email,
                name: user.name,
                metadata: { userId: user.id }
            });
            customerId = customer.id;
            await prisma.user.update({
                where: { id: user.id },
                data: { stripeCustomerId: customerId }
            });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            customer: customerId,
            line_items: [{ price: priceId, quantity: 1 }],
            mode: 'subscription',
            success_url: `${process.env.FRONTEND_URL}/dashboard?success=true`,
            cancel_url: `${process.env.FRONTEND_URL}/checkout?canceled=true`,
            metadata: {
                userId: user.id,
                planType: planType
            }
        });

        res.json({ url: session.url });

    } catch (error) {
        console.error("Erro checkout:", error);
        res.status(500).json({ error: 'Erro ao criar checkout' });
    }
});

// Novo endpoint para cancelamento direto de assinatura
app.post('/tato/v2/payment/cancel-subscription', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (!user.stripeSubscriptionId) {
            return res.status(400).json({ error: 'Nenhuma assinatura ativa encontrada.' });
        }

        // Cancela a assinatura no Stripe imediatamente
        await stripe.subscriptions.cancel(user.stripeSubscriptionId);

        // Atualiza o banco de dados localmente
        await prisma.user.update({
            where: { id: user.id },
            data: {
                subscriptionStatus: 'canceled',
                planType: 'TRIAL' // Retorna para plano base/trial ou encerra
            }
        });

        res.json({ success: true, message: 'Assinatura cancelada com sucesso.' });

    } catch (error) {
        console.error("Erro ao cancelar assinatura:", error);
        res.status(500).json({ error: 'Erro ao cancelar assinatura.' });
    }
});

app.post('/tato/v2/payment/customer-portal', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (!user.stripeCustomerId) {
            return res.status(400).json({ error: 'Usuário não possui assinatura ativa.' });
        }

        const session = await stripe.billingPortal.sessions.create({
            customer: user.stripeCustomerId,
            return_url: `${process.env.FRONTEND_URL}/dashboard`,
        });

        res.json({ url: session.url });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao acessar portal' });
    }
});

app.get('/tato/v2/payment/links', (req, res) => {
    res.json({
        essential: process.env.STRIPE_LINK_ESSENTIAL,
        professional: process.env.STRIPE_LINK_PROFESSIONAL
    });
});

// --- ROTA REGISTER (COM PROTEÇÃO DE TRIAL E UPSERT) ---
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

        const trialEnds = new Date();
        if (abuse) {
            trialEnds.setDate(trialEnds.getDate() - 1);
            console.log(`[Registro] Abuso detectado para ${email}. Restaurando uso: ${usageHistory}`);
        } else {
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
                    messagesUsed: abuse ? usageHistory : 0,
                    subscriptionStatus: 'active',
                    fingerprint: fingerprint || null
                },
                select: { id: true }
            });

            await prisma.trialLog.upsert({
                where: { emailHash },
                update: { fingerprint: fingerprint || null },
                create: {
                    emailHash,
                    fingerprint: fingerprint || null,
                    usageHistory: 0
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

// --- ROTA GOOGLE AUTH (COM PROTEÇÃO E UPSERT) ---
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
                        messagesUsed: abuse ? usageHistory : 0
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

// --- ROTA DELETAR CONTA (COM CANCELAMENTO NO STRIPE) ---
app.delete('/tato/v2/user/delete', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });

        if (user) {
            // 1. Tenta cancelar a assinatura no Stripe se existir
            if (user.stripeSubscriptionId) {
                try {
                    await stripe.subscriptions.cancel(user.stripeSubscriptionId);
                    console.log(`[Delete] Assinatura ${user.stripeSubscriptionId} cancelada no Stripe.`);
                } catch (stripeError) {
                    // Loga o erro, mas não impede a deleção da conta local
                    console.error("Erro ao cancelar assinatura no Stripe durante delete:", stripeError.message);
                }
            }

            // 2. Salva uso atual no log permanente
            const emailHash = crypto.createHash('sha256').update(user.email.toLowerCase().trim()).digest('hex');

            await prisma.trialLog.upsert({
                where: { emailHash },
                update: { usageHistory: user.messagesUsed },
                create: {
                    emailHash,
                    fingerprint: user.fingerprint,
                    usageHistory: user.messagesUsed
                }
            });

            await prisma.user.delete({ where: { id: decoded.userId } });
            res.json({ success: true, message: 'Conta deletada e assinatura cancelada.' });
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
            nextBilling = user.nextBillingDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
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
            account: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        return res.status(403).json({ error: 'Sessão inválida' });
    }
});

// --- ROTA VALIDATE USAGE (BLOQUEIO E CONTROLE) ---
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

// --- ROTA METRICS (ADMIN) ---
app.get('/tato/v2/admin/metrics', async (req, res) => {
    // Rota pública para dashboard de métricas (sem autenticação)

    try {
        const now = new Date();
        const thirtyDaysAgo = new Date(now);
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        // 1. Usuários Ativos (MAU) - Ativos nos últimos 30 dias
        // Consideramos ativo quem atualizou algo (login, uso, etc)
        const mauCount = await prisma.user.count({
            where: {
                updatedAt: {
                    gte: thirtyDaysAgo
                }
            }
        });

        // 2. Mensagens Refinadas (Total)
        const messagesRefinedAggregate = await prisma.user.aggregate({
            _sum: {
                messagesUsed: true
            }
        });
        const totalMessagesRefined = messagesRefinedAggregate._sum.messagesUsed || 0;

        // 3. Retenção D30
        // Definição: Usuários criados há mais de 30 dias que ainda estão ativos (updatedAt recente ou assinatura ativa)
        const cohortDate = thirtyDaysAgo; // Usuários criados ANTES disso

        const cohortCount = await prisma.user.count({
            where: {
                createdAt: {
                    lt: cohortDate
                }
            }
        });

        let retentionD30 = 0;
        if (cohortCount > 0) {
            const retainedCount = await prisma.user.count({
                where: {
                    createdAt: {
                        lt: cohortDate
                    },
                    OR: [
                        { updatedAt: { gte: thirtyDaysAgo } }, // Usou recentemente
                        { subscriptionStatus: 'active' }       // Ou paga
                    ]
                }
            });
            retentionD30 = (retainedCount / cohortCount) * 100;
        }

        // 4. Crescimento (Últimos 12 meses)
        const growth = [];
        for (let i = 11; i >= 0; i--) {
            const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const nextMonth = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);

            const count = await prisma.user.count({
                where: {
                    createdAt: {
                        gte: date,
                        lt: nextMonth
                    }
                }
            });

            growth.push({
                month: date.toLocaleString('default', { month: 'short', year: 'numeric' }),
                users: count
            });
        }

        res.json({
            mau: mauCount,
            totalMessagesRefined,
            retentionD30: parseFloat(retentionD30.toFixed(2)),
            growth
        });

    } catch (error) {
        console.error("Erro Metrics:", error);
        res.status(500).json({ error: 'Erro ao buscar métricas.' });
    }
});

if (process.env.NODE_ENV !== 'production') app.listen(port, () => console.log(`API running on ${port}`));

export default app;