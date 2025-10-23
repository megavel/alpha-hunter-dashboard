const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const admin = require('firebase-admin');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.set('trust proxy', true);

// === ENHANCED LOGGING ===
const log = {
    info: (msg, ...args) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`, ...args),
    error: (msg, ...args) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`, ...args),
    warn: (msg, ...args) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`, ...args),
    webhook: (msg, ...args) => console.log(`[WEBHOOK] ${new Date().toISOString()} - ${msg}`, ...args)
};

// === FIREBASE SETUP ===
let db = null;
let firebaseInitialized = false;

function loadServiceAccountFromEnv() {
    // Prefer unified JSON via FIREBASE_SERVICE_ACCOUNT (supports base64 or plain JSON)
    const svc = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (svc) {
        try {
            const maybeJson = svc.trim();
            const parsed = maybeJson.startsWith('{')
                ? JSON.parse(maybeJson)
                : JSON.parse(Buffer.from(maybeJson, 'base64').toString('utf-8'));
            return parsed;
        } catch (e) {
            log.error('Failed to parse FIREBASE_SERVICE_ACCOUNT. Ensure it is valid JSON or base64 JSON.');
        }
    }

    // Fallback to split env vars
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (projectId && clientEmail && privateKey) {
        // Handle escaped newlines from env storage
        privateKey = privateKey.replace(/\\n/g, '\n');
        return { project_id: projectId, client_email: clientEmail, private_key: privateKey };
    }

    return null;
}

try {
    log.info('Initializing Firebase Admin...');
    if (!admin.apps.length) {
        const serviceAccount = loadServiceAccountFromEnv();
        if (!serviceAccount) {
            throw new Error('Firebase credentials not provided. Set FIREBASE_SERVICE_ACCOUNT (JSON or base64) or FIREBASE_PROJECT_ID/CLIENT_EMAIL/PRIVATE_KEY');
        }

        const redactedKeyInfo = serviceAccount.private_key ? `privKey(${serviceAccount.private_key.length} chars)` : 'no-privKey';
        log.info(`Firebase creds: project=${serviceAccount.project_id || 'n/a'} email=${serviceAccount.client_email || 'n/a'} ${redactedKeyInfo}`);

        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });

        firebaseInitialized = true;
        db = admin.firestore();
        log.info('✅ Firebase Admin initialized successfully');
    }
} catch (error) {
    log.error('❌ Firebase initialization failed:', error.message);
}

// === MIDDLEWARE ===
app.use(cors());

// Webhook endpoint needs raw body (ensure it works behind Vercel rewrites)
const rawBodyMiddleware = express.raw({
    type: '*/*',
    limit: '5mb',
    verify: (req, res, buf, encoding) => {
        if (buf && buf.length) {
            req.rawBody = buf.toString(encoding || 'utf8');
        }
    }
});
app.use('/api/payment-webhook', rawBodyMiddleware);
// Extra: handle cases where rewrites deliver to /api/server
app.use('/api/server', rawBodyMiddleware);

// Other routes use JSON
app.use(express.json({ limit: '1mb' }));

// Static files (for Vercel)
const publicPath = path.join(__dirname, '..', 'public');
app.use(express.static(publicPath));

// === CONFIG ===
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const SHEET_ID = process.env.SHEET_ID;
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;
const NOWPAYMENTS_IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET;
const IS_SANDBOX = process.env.NOWPAYMENTS_SANDBOX === 'true';
const NOWPAYMENTS_BASE_URL = IS_SANDBOX 
    ? 'https://api-sandbox.nowpayments.io/v1' 
    : 'https://api.nowpayments.io/v1';
// Public canonical base URL for building callbacks/redirects
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').trim().replace(/\/$/, '');

log.info(`NOWPayments Mode: ${IS_SANDBOX ? 'SANDBOX' : 'LIVE'}`);
log.info(`Firebase Ready: ${firebaseInitialized}`);

// === GOOGLE SHEETS API ===
let sheetsCache = {};
let sheetsLastFetch = {};
const CACHE_DURATION = 5 * 60 * 1000;

app.get('/api/sheets/data', async (req, res) => {
    const sheetName = req.query.sheet || 'Sheet1';
    
    try {
        // Check cache
        if (sheetsCache[sheetName] && sheetsLastFetch[sheetName] && 
            (Date.now() - sheetsLastFetch[sheetName] < CACHE_DURATION)) {
            return res.json(sheetsCache[sheetName]);
        }
        
        if (!GOOGLE_API_KEY || !SHEET_ID) {
            return res.status(500).json({ error: 'Server configuration error' });
        }
        
        const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${sheetName}?key=${GOOGLE_API_KEY}`;
        const response = await fetch(url);
        
        if (!response.ok) {
            const errorText = await response.text();
            log.error(`Sheets API error ${response.status}:`, errorText);
            throw new Error(`Failed to fetch sheet: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!data.values || data.values.length === 0) {
            return res.status(404).json({ error: 'No data found' });
        }
        
        const headers = data.values[0];
        const rows = data.values.slice(1)
            .filter(row => row.some(cell => cell != null && cell !== ''))
            .map(row => {
                const obj = {};
                headers.forEach((header, i) => {
                    obj[header] = row[i] || '';
                });
                return obj;
            });
        
        sheetsCache[sheetName] = rows;
        sheetsLastFetch[sheetName] = Date.now();
        
        log.info(`Fetched ${rows.length} rows from ${sheetName}`);
        res.json(rows);
        
    } catch (error) {
        log.error(`Error fetching ${sheetName}:`, error.message);
        res.status(500).json({ error: 'Failed to fetch data', message: error.message });
    }
});

// === CHECK ACCESS ===
app.get('/api/check-access', async (req, res) => {
    const { wallet } = req.query;
    
    if (!wallet) {
        return res.status(400).json({ error: 'Wallet address required' });
    }
    
    if (!db) {
        log.error("Check access failed: Firestore not initialized");
        return res.status(500).json({ error: 'Database unavailable' });
    }
    
    try {
        const walletLower = wallet.toLowerCase();
        const userRef = db.collection('paid_users').doc(walletLower);
        const doc = await userRef.get();
        
        let hasAccess = false;
        
        if (doc.exists) {
            const data = doc.data();
            const expiryTimestamp = data.expiryDate;
            
            if (expiryTimestamp) {
                const expiryDate = expiryTimestamp.toDate();
                hasAccess = expiryDate > new Date();
                
                log.info(`Access check for ${walletLower}: ${hasAccess ? 'GRANTED' : 'EXPIRED'} (Expiry: ${expiryDate.toISOString()})`);
            } else {
                log.warn(`User ${walletLower} exists but no expiryDate`);
            }
        } else {
            log.info(`Access check for ${walletLower}: NOT FOUND`);
        }
        
        res.json({ hasAccess });
        
    } catch (error) {
        log.error('Check access error:', error.message);
        res.status(500).json({ error: 'Failed to check access', message: error.message });
    }
});

// === CREATE PAYMENT ===
app.post('/api/create-payment', async (req, res) => {
    const { walletAddress, plan = 'monthly' } = req.body;
    
    if (!walletAddress) {
        return res.status(400).json({ error: 'Wallet address required' });
    }
    
    if (!NOWPAYMENTS_API_KEY) {
        return res.status(500).json({ error: 'Payment system not configured' });
    }
    
    const paymentAmount = parseFloat(process.env.MONTHLY_PRICE || 50);
    const paymentCurrency = process.env.PAYMENT_CURRENCY || 'usd';
    
    try {
        // Determine canonical base URL for callbacks/redirects
        let baseUrl = PUBLIC_BASE_URL;
        if (!baseUrl) {
            const forwardedProto = req.headers['x-forwarded-proto'];
            const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${process.env.PORT || 3000}`;
            const proto = forwardedProto || (hostHeader.includes('localhost') ? 'http' : 'https');
            baseUrl = `${proto}://${hostHeader}`;
        }

        const ipnCallbackUrl = `${baseUrl}/api/payment-webhook`;
        const successUrl = `${baseUrl}/?payment=success`;
        const cancelUrl = `${baseUrl}/?payment=failed`;
        
        log.info(`Creating payment for ${walletAddress.toLowerCase()}`);
        log.info(`Base URL: ${baseUrl}`);
        log.info(`IPN Callback: ${ipnCallbackUrl}`);
        
        const response = await fetch(`${NOWPAYMENTS_BASE_URL}/invoice`, {
            method: 'POST',
            headers: {
                'x-api-key': NOWPAYMENTS_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                price_amount: paymentAmount,
                price_currency: paymentCurrency,
                order_id: walletAddress.toLowerCase(),
                order_description: `Alpha Hunter ${plan.charAt(0).toUpperCase() + plan.slice(1)} Access`,
                ipn_callback_url: ipnCallbackUrl,
                success_url: successUrl,
                cancel_url: cancelUrl
            })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            log.error('NOWPayments API error:', data);
            throw new Error(data.message || `Failed to create invoice: ${response.status}`);
        }
        
        if (!data.invoice_url) {
            log.error('Invoice created but no URL returned:', data);
            throw new Error('Invoice URL not returned');
        }
        
        log.info(`✅ Invoice created: ${data.id}`);
        res.json({ invoice_url: data.invoice_url });
        
    } catch (error) {
        log.error('Create payment error:', error.message);
        res.status(500).json({ error: 'Failed to create payment', message: error.message });
    }
});

// === PAYMENT WEBHOOK ===
async function handleNowPaymentsWebhook(req, res) {
    log.webhook('=== WEBHOOK RECEIVED ===');
    
    const signature = req.headers['x-nowpayments-sig'];
    let rawBody = req.rawBody;
    
    // Validate prerequisites
    if (!NOWPAYMENTS_IPN_SECRET) {
        log.error('IPN Secret not configured');
        return res.status(500).send('Webhook not configured');
    }
    
    if (!db) {
        log.error('Firestore not initialized');
        return res.status(500).send('Database unavailable');
    }
    
    if (!signature) {
        log.warn('Webhook missing signature');
        return res.status(401).send('Signature missing');
    }
    
    // Fallbacks if raw body was pre-parsed by the platform
    if (!rawBody) {
        if (typeof req.body === 'string') {
            rawBody = req.body;
            log.webhook('Using string req.body as raw body fallback');
        } else if (Buffer.isBuffer(req.body)) {
            rawBody = req.body.toString('utf8');
            log.webhook('Using buffer req.body as raw body fallback');
        } else if (req.body && typeof req.body === 'object') {
            // As a last resort; signature may fail if whitespace differs
            rawBody = JSON.stringify(req.body);
            log.warn('Using JSON.stringify(req.body) as raw body fallback; signature may not match');
        }
    }

    if (!rawBody) {
        log.error('Raw body not available after fallbacks');
        return res.status(500).send('Cannot read request body');
    }
    
    // Parse body
    let body;
    try {
        body = JSON.parse(rawBody);
        log.webhook('Body parsed:', JSON.stringify(body, null, 2));
    } catch (e) {
        log.error('Invalid JSON in webhook body');
        return res.status(400).send('Invalid JSON');
    }
    
    try {
        // Verify signature
        const hmac = crypto.createHmac('sha512', NOWPAYMENTS_IPN_SECRET);
        hmac.update(rawBody);
        const calculatedSig = hmac.digest('hex');
        
        if (calculatedSig !== signature) {
            const msg = `Signature mismatch (expected ${calculatedSig}, received ${signature})`;
            if (IS_SANDBOX) {
                log.warn(`${msg}. Continuing due to SANDBOX mode.`);
            } else {
                log.error(msg);
                return res.status(401).send('Invalid signature');
            }
        }
        
        log.webhook('✅ Signature verified');
        
        const { payment_status, order_id, subscription_id, id } = body;
        
        log.webhook(`Status: ${payment_status}`);
        log.webhook(`Order ID: ${order_id}`);
        log.webhook(`Subscription ID: ${subscription_id}`);
        log.webhook(`Payment ID: ${id}`);
        
        // Process successful payments
        const successStatuses = ['finished', 'confirmed', 'sending'];
        
        if (successStatuses.includes(payment_status)) {
            let walletAddress = null;
            let userRef = null;
            
            // Find user by subscription_id or order_id
            if (subscription_id) {
                log.webhook('Processing renewal payment');
                const query = db.collection('paid_users')
                    .where('subscriptionId', '==', subscription_id)
                    .limit(1);
                    
                const snapshot = await query.get();
                
                if (!snapshot.empty) {
                    const userDoc = snapshot.docs[0];
                    walletAddress = userDoc.id;
                    userRef = userDoc.ref;
                    log.webhook(`Found user: ${walletAddress}`);
                } else {
                    log.error(`No user found for subscription: ${subscription_id}`);
                    return res.status(200).send('User not found');
                }
            } else if (order_id) {
                log.webhook('Processing initial payment');
                walletAddress = order_id.toLowerCase();
                userRef = db.collection('paid_users').doc(walletAddress);
            } else {
                log.error('Cannot identify user - missing order_id and subscription_id');
                return res.status(400).send('Cannot identify user');
            }
            
            // Update Firestore
            if (walletAddress && userRef) {
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + 30);
                
                const updateData = {
                    paid: true,
                    status: payment_status,
                    expiryDate: admin.firestore.Timestamp.fromDate(expiryDate),
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                };
                
                // Only add fields if they exist (avoid undefined)
                if (id) {
                    updateData.lastPaymentId = id;
                }
                
                if (subscription_id) {
                    updateData.subscriptionId = subscription_id;
                }
                
                log.webhook(`Updating Firestore for ${walletAddress}`);
                log.webhook(`New expiry: ${expiryDate.toISOString()}`);
                
                await userRef.set(updateData, { merge: true });
                
                log.webhook('✅ Firestore updated successfully');
            }
        } else {
            log.webhook(`Unhandled status: ${payment_status}`);
        }
        
        log.webhook('=== WEBHOOK PROCESSED ===');
        res.status(200).send('OK');
        
    } catch (error) {
        log.error('Webhook processing error:', error);
        res.status(500).send('Internal error');
    }
}

// Mount webhook handler for both the intended path and the rewritten target
app.post('/api/payment-webhook', handleNowPaymentsWebhook);
app.post('/api/server', (req, res, next) => {
    // Only treat as webhook if NOWPayments signature header present
    if (req.headers && req.headers['x-nowpayments-sig']) {
        return handleNowPaymentsWebhook(req, res);
    }
    return res.status(404).send('Not Found');
});

// === MANUAL ACCESS GRANT (Testing) ===
app.post('/api/grant-access-manual', async (req, res) => {
    const { walletAddress, secret } = req.body;
    
    if (secret !== process.env.ADMIN_SECRET) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!db) {
        return res.status(500).json({ error: 'Database unavailable' });
    }
    
    try {
        const wallet = walletAddress.toLowerCase();
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 30);
        
        await db.collection('paid_users').doc(wallet).set({
            paid: true,
            status: 'finished',
            expiryDate: admin.firestore.Timestamp.fromDate(expiryDate),
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            manual: true
        }, { merge: true });
        
        log.info(`✅ Manual access granted to ${wallet}`);
        res.json({ success: true, wallet, expiresAt: expiryDate.toISOString() });
        
    } catch (error) {
        log.error('Manual grant error:', error);
        res.status(500).json({ error: error.message });
    }
});

// === HEALTH CHECK ===
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        firebase: firebaseInitialized,
        sandbox: IS_SANDBOX
    });
});

// === CACHE CLEAR ===
app.post('/api/sheets/clear-cache', (req, res) => {
    sheetsCache = {};
    sheetsLastFetch = {};
    res.json({ message: 'Cache cleared' });
});

// === SPA FALLBACK (for local dev) ===
if (require.main === module) {
    app.get('*', (req, res, next) => {
        if (!req.path.startsWith('/api/')) {
            res.sendFile(path.join(publicPath, 'index.html'));
        } else {
            next();
        }
    });
}

// === START SERVER (local only) ===
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        log.info(`🚀 Server running on http://localhost:${PORT}`);
        log.info(`Firebase: ${firebaseInitialized ? '✅' : '❌'}`);
        log.info(`NOWPayments: ${IS_SANDBOX ? 'SANDBOX' : 'LIVE'}`);
    });
}

// === VERCEL EXPORT ===
module.exports = app;