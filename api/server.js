const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch'); // Ensure v2 for CommonJS
const admin = require('firebase-admin');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();

// --- Firebase Admin Setup ---
let db = null;
let firebaseInitialized = false;
try {
    console.log("Attempting Firebase Admin initialization...");
    if (!admin.apps.length) {
        if (!process.env.FIREBASE_SERVICE_ACCOUNT) throw new Error("FIREBASE_SERVICE_ACCOUNT env var not set.");
        const serviceAccountBase64 = process.env.FIREBASE_SERVICE_ACCOUNT;
        if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(serviceAccountBase64)) throw new Error("FIREBASE_SERVICE_ACCOUNT not valid Base64.");
        console.log("Decoding/Parsing FIREBASE_SERVICE_ACCOUNT...");
        const serviceAccountJson = Buffer.from(serviceAccountBase64, 'base64').toString('utf-8');
        const serviceAccount = JSON.parse(serviceAccountJson);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        firebaseInitialized = true;
        console.log("Firebase Admin Initialized Successfully");
    } else {
        firebaseInitialized = true;
        console.log("Firebase Admin already initialized.");
    }
    if (firebaseInitialized) {
        db = admin.firestore();
        console.log("Firestore instance obtained successfully.");
    } else {
         console.error("Firebase Admin not initialized, cannot get Firestore instance.");
    }
} catch (error) {
    console.error('Firebase Admin Initialization/Firestore Setup Error:', error.message);
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        const envVarContent = process.env.FIREBASE_SERVICE_ACCOUNT;
        console.error(`FIREBASE_SERVICE_ACCOUNT length: ${envVarContent.length}`);
        console.error(`Starts/Ends with: ${envVarContent.substring(0, 20)}...${envVarContent.substring(envVarContent.length - 20)}`);
    }
}

// --- Middleware & Config ---
app.use(cors());
const rawBodySaver = (req, res, buf, encoding) => { if (buf && buf.length) { req.rawBody = buf.toString(encoding || 'utf8'); } };
app.use('/api/payment-webhook', express.raw({ verify: rawBodySaver, type: '*/*', limit: '5mb' }));
app.use(express.json({ limit: '1mb' })); // JSON parser for other routes

const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const SHEET_ID = process.env.SHEET_ID;
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;
const NOWPAYMENTS_IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET;
const IS_SANDBOX = process.env.NOWPAYMENTS_SANDBOX === 'true';
const NOWPAYMENTS_BASE_URL = IS_SANDBOX ? 'https://api-sandbox.nowpayments.io/v1' : 'https://api.nowpayments.io/v1';
console.log(`NOWPayments Mode: ${IS_SANDBOX ? 'Sandbox' : 'Live'}, Base URL: ${NOWPAYMENTS_BASE_URL}`);

// --- Google Sheets API (/api/sheets/data) ---
let sheetsCache = {};
let sheetsLastFetch = {};
const CACHE_DURATION = 5 * 60 * 1000;
app.get('/api/sheets/data', async (req, res) => { /* ... unchanged ... */
    const sheetName = req.query.sheet || 'Sheet1';
    try { if (sheetsCache[sheetName] && sheetsLastFetch[sheetName] && (Date.now() - sheetsLastFetch[sheetName] < CACHE_DURATION)) { return res.json(sheetsCache[sheetName]); }
        if (!GOOGLE_API_KEY || !SHEET_ID) { console.error("Sheets Error: Missing Google creds."); return res.status(500).json({ error: 'Server config error' }); }
        const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${sheetName}?key=${GOOGLE_API_KEY}`;
        const response = await fetch(url);
        if (!response.ok) { const txt = await response.text(); console.error(`Sheets Error ${response.status}: ${txt}`); throw new Error(`Fetch failed ${response.status}`); }
        const data = await response.json();
        if (!data.values || data.values.length === 0) { console.log(`Sheets Info: No data in ${sheetName}`); return res.status(404).json({ error: 'No data' }); }
        const headers = data.values[0];
        const rows = data.values.slice(1).filter(r => r.some(c => c != null && c !== '')).map(r => { const o = {}; headers.forEach((h, i) => { o[h] = r[i] || ''; }); return o; });
        sheetsCache[sheetName] = rows; sheetsLastFetch[sheetName] = Date.now();
        console.log(`Sheets Success: Fetched ${rows.length} rows from ${sheetName}`);
        res.json(rows);
    } catch (error) { console.error(`Sheets Error fetching ${sheetName}:`, error); res.status(500).json({ error: 'Fetch failed', message: error.message }); }
});


// --- PAYWALL API ENDPOINTS ---

app.get('/api/check-access', async (req, res) => {
    // This logic remains the same - check for document and expiryDate > now
    const { wallet } = req.query;
    if (!wallet) { return res.status(400).json({ error: 'Wallet address is required' }); }
    if (!db) { return res.status(500).json({ error: 'Database service unavailable' }); }
    try {
        const walletLower = wallet.toLowerCase();
        console.log(`CHECK-ACCESS Info: Reading doc: paid_users/${walletLower}`);
        const userRef = db.collection('paid_users').doc(walletLower);
        const doc = await userRef.get();
        let hasAccess = false;
        if (doc.exists) {
            const data = doc.data();
            const expiryTimestamp = data.expiryDate;
            if (expiryTimestamp && expiryTimestamp.toDate() > new Date()) {
                hasAccess = true;
                console.log(`CHECK-ACCESS Info: Access GRANTED for ${walletLower}. Expiry: ${expiryTimestamp.toDate().toISOString()}`);
            } else if (expiryTimestamp) {
                console.log(`CHECK-ACCESS Info: Access EXPIRED for ${walletLower}. Expiry: ${expiryTimestamp.toDate().toISOString()}`);
            } else { console.log(`CHECK-ACCESS Info: User ${walletLower} exists but has no expiryDate.`); }
        } else { console.log(`CHECK-ACCESS Info: User ${walletLower} not found.`); }
        res.json({ hasAccess: hasAccess });
    } catch (error) { console.error('CHECK-ACCESS Error reading Firestore:', error); res.status(500).json({ error: 'Failed to check wallet access', message: error.message }); }
});

// REVERTED: Create a standard one-time INVOICE for the initial payment.
app.post('/api/create-payment', async (req, res) => {
    const { walletAddress, plan = 'monthly' } = req.body; // Still accept plan for potential future use
    if (!walletAddress) { return res.status(400).json({ error: 'Wallet address is required' }); }
    if (!NOWPAYMENTS_API_KEY) { return res.status(500).json({ error: 'Payment processor API key not configured' }); }

    // Use plan details for the invoice amount/currency
    let paymentDetails;
     if (plan === 'monthly') {
         paymentDetails = {
             amount: process.env.MONTHLY_PRICE || 50, // Default $50
             currency: process.env.PAYMENT_CURRENCY || 'usd',
             description: 'Alpha Hunter Monthly Access (First Month)'
         };
     }
     // else if (plan === 'quarterly') { /* ... details ... */ }
     // else if (plan === 'yearly') { /* ... details ... */ }
     else {
         return res.status(400).json({ error: 'Invalid plan specified for initial payment' });
     }

    try {
        const host = process.env.VERCEL_URL || req.headers['x-forwarded-host'] || req.headers.host || `localhost:${process.env.PORT || 3000}`;
        const protocol = host.includes('localhost') ? 'http' : 'https';
        const ipnCallbackUrl = `${protocol}://${host}/api/payment-webhook`;
        const successUrl = `${protocol}://${host}/?payment=success`; // Back to homepage
        const cancelUrl = `${protocol}://${host}/?payment=failed`;  // Back to homepage

        console.log(`CREATE-INVOICE Info: Initiating for ${walletAddress.toLowerCase()} (${plan}) via ${NOWPAYMENTS_BASE_URL}/invoice...`);

        // *** Use the /invoice endpoint ***
        const response = await fetch(`${NOWPAYMENTS_BASE_URL}/invoice`, {
             method: 'POST',
             headers: { 'x-api-key': NOWPAYMENTS_API_KEY, 'Content-Type': 'application/json' },
             body: JSON.stringify({
                 price_amount: paymentDetails.amount,
                 price_currency: paymentDetails.currency,
                 order_id: walletAddress.toLowerCase(), // Use wallet address as the unique ID for this invoice
                 order_description: paymentDetails.description,
                 ipn_callback_url: ipnCallbackUrl,
                 success_url: successUrl,
                 cancel_url: cancelUrl,
                 // ** Optional: Link to a pre-defined Plan ID if API supports it **
                 // subscription_plan_id: 'YOUR_PLAN_ID_FROM_NOWPAYMENTS' // Check NOWPayments docs if this field exists for /invoice
             })
        });

        const data = await response.json();
        if (!response.ok) {
            console.error('CREATE-INVOICE Error: NOWPayments API Error response:', data);
            throw new Error(data.message || `Failed to create invoice. Status: ${response.status}`);
        }
        if (!data.invoice_url) {
             console.error('CREATE-INVOICE Error: NOWPayments success response missing invoice_url:', data);
             throw new Error('Invoice created, but invoice URL was not returned.');
        }

        console.log(`CREATE-INVOICE Success: Invoice ${data.id} created for initial payment.`);
        // Return the standard invoice URL for the user to pay
        res.json({ invoice_url: data.invoice_url });

    } catch (error) {
        console.error('CREATE-INVOICE Error:', error);
        res.status(500).json({ error: 'Failed to create initial payment invoice', message: error.message });
    }
});


// UPDATED: Handle webhooks potentially for subscriptions OR one-time invoices
app.post('/api/payment-webhook', async (req, res) => {
    console.log('--- WEBHOOK: Received ---');
    const signature = req.headers['x-nowpayments-sig'];
    const rawBody = req.rawBody;

    // --- Initial Checks ---
    if (!NOWPAYMENTS_IPN_SECRET) { /* ... */ return res.status(500).send('Webhook config error'); }
    if (!db) { /* ... */ return res.status(500).send('DB service unavailable'); }
    if (!signature) { /* ... */ return res.status(401).send('Signature missing'); }
    if (!rawBody) { /* ... */ return res.status(500).send('Internal Error: Could not read body'); }

    // --- Body Parsing ---
    let body;
    try { body = JSON.parse(rawBody); }
    catch (e) { /* ... */ return res.status(400).send('Invalid JSON'); }

    try {
        // --- Signature Verification ---
        console.log("Webhook: Verifying signature...");
        let areSignaturesEqual = false;
        try { /* ... hmac verification ... */
            const hmac = crypto.createHmac('sha512', NOWPAYMENTS_IPN_SECRET); hmac.update(rawBody); const calculatedSig = hmac.digest('hex');
            const sigBuffer = Buffer.from(signature, 'hex'); const calcSigBuffer = Buffer.from(calculatedSig, 'hex');
            if (sigBuffer.length === calcSigBuffer.length) { areSignaturesEqual = crypto.timingSafeEqual(calcSigBuffer, sigBuffer); }
            else { console.warn("Webhook Warn: Sig length mismatch."); }
        } catch (e) { console.error("Webhook Error: Sig comparison failed.", e.message); }
        if (!areSignaturesEqual) { /* ... */ return res.status(401).send('Invalid signature'); }
        console.log("Webhook: Signature VERIFIED.");
        // --- End Signature Verification ---

        const {
            payment_status,
            order_id,         // Should be the wallet address for our initial invoices
            subscription_id,  // Might be present for renewals triggered by a plan
            id                // The unique ID of this specific payment/transaction
        } = body;

        console.log(`Webhook Info: Received Status='${payment_status}', SubID='${subscription_id}', OrderID='${order_id}', PaymentID='${id}'`);

        // Process only successful payments
        const successfulStatuses = ['finished', 'confirming', 'confirmed', 'sending', 'partially_paid'];
        if (successfulStatuses.includes(payment_status)) {

            let walletAddress = null;
            let userRef = null;

            // --- Identify the user ---
            if (subscription_id) {
                // Payment is likely a renewal, find user by subscription_id
                console.log(`Webhook Info: Processing RENEWAL payment for SubID: ${subscription_id}`);
                const usersQuery = db.collection('paid_users').where('subscriptionId', '==', subscription_id).limit(1);
                const querySnapshot = await usersQuery.get();
                if (!querySnapshot.empty) {
                    userDoc = querySnapshot.docs[0];
                    walletAddress = userDoc.id;
                    userRef = userDoc.ref;
                    console.log(`Webhook Info: Found user ${walletAddress} for subscription ${subscription_id}.`);
                } else {
                    console.error(`WEBHOOK REJECTED: No user found matching subscriptionId: ${subscription_id}`);
                    return res.status(200).send('Webhook processed (unknown subscription)'); // Acknowledge to prevent retries
                }
            } else if (order_id) {
                // Payment is likely the INITIAL invoice, user identified by order_id (wallet address)
                 console.log(`Webhook Info: Processing INITIAL payment for OrderID: ${order_id}`);
                 walletAddress = order_id.toLowerCase();
                 userRef = db.collection('paid_users').doc(walletAddress);
            } else {
                 console.error(`WEBHOOK REJECTED: Cannot identify user - Missing both subscription_id and order_id.`);
                 return res.status(400).send('Cannot identify user from webhook'); // Bad request
            }

            // --- Update Firestore Record ---
            if (walletAddress && userRef) {
                try {
                    // Calculate new expiry date (+30 days from now)
                    // TODO: Adjust calculation based on plan (monthly/quarterly/yearly) if needed later
                    const now = new Date();
                    // Start from 'now' for renewals, consider starting from previous expiry if available and needed
                    const expiryDate = new Date(new Date().setDate(now.getDate() + 30));
                    const expiryTimestamp = admin.firestore.Timestamp.fromDate(expiryDate);
                    console.log(`Webhook DB Write: Updating expiry for ${walletAddress} to ${expiryDate.toISOString()}`);

                    const updateData = {
                        status: payment_status,
                        lastPaymentId: id || null,
                        expiryDate: expiryTimestamp, // Set/Update the expiry date
                        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                        // Set 'paid' flag reliably only when status is definitively 'finished'
                        ...(payment_status === 'finished' && { paid: true })
                    };

                    // Add subscriptionId if it came with the webhook (useful for renewals)
                    if (subscription_id) {
                        updateData.subscriptionId = subscription_id;
                    }

                    // Use set with merge:true for the initial payment, update for renewals
                    // Let's simplify: always use set with merge:true to handle both cases
                    console.log(`Webhook DB Write: Performing set(merge:true) for ${walletAddress}...`);
                    await userRef.set(updateData, { merge: true });
                    console.log(`Webhook DB Write Success: Record updated/created for ${walletAddress}.`);

                } catch (dbError) {
                    console.error(`Webhook DB Error updating record for ${walletAddress}:`, dbError);
                    return res.status(500).send('Database update failed'); // Let NOWPayments retry
                }
            } else {
                 // Should not happen if logic above is correct, but added as safety
                 console.error(`Webhook Error: Could not determine walletAddress or userRef.`);
            }

        }
        // Handle failed/expired payments (optional)
        else if (payment_status === 'failed' || payment_status === 'expired') {
            console.warn(`Webhook Warn: Payment ${payment_status} received. SubID: ${subscription_id}, OrderID: ${order_id}`);
            // Optionally find the user and update their status to 'failed' or 'expired' in Firestore
            // let userRef = null;
            // if (subscription_id) { ... find by sub id ... } else if (order_id) { userRef = db.collection('paid_users').doc(order_id.toLowerCase()); }
            // if (userRef) { await userRef.update({ status: payment_status, updatedAt: admin.firestore.FieldValue.serverTimestamp() }); }
        }
        else {
            console.log(`Webhook Info: Unhandled status '${payment_status}'. SubID: ${subscription_id}, OrderID: ${order_id}. No DB action.`);
        }

        console.log('--- Webhook Processed OK ---');
        res.status(200).send('Webhook processed');

    } catch (error) {
        console.error('Webhook UNEXPECTED Error:', error);
        res.status(500).send('Internal server error');
    }
});


// --- Health Check & Cache Clear ---
app.get('/api/health', (req, res) => { res.json({ status: 'ok', timestamp: new Date().toISOString() }); });
app.post('/api/sheets/clear-cache', (req, res) => { sheetsCache = {}; sheetsLastFetch = {}; res.json({ message: 'Cache cleared' }); });

// --- Local Development Server Setup ---
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    const publicPath = path.join(__dirname, '..', 'public');
    app.use(express.static(publicPath));
    app.get('*', (req, res, next) => { /* ... SPA catch-all ... */
         if (!req.path.startsWith('/api/')) { const fp = path.join(publicPath, req.path); res.sendFile(fp, (err) => { if (err) { res.sendFile(path.join(publicPath, 'index.html')); } }); }
         else { next(); }
    });
    app.listen(PORT, () => {
        console.log(`\nServer running locally on http://localhost:${PORT}`);
        console.log(`Firebase Initialized: ${firebaseInitialized}, Firestore Ready: ${!!db}`);
        console.log(`NOWPayments Sandbox Mode: ${IS_SANDBOX}\n`);
    });
}

// Vercel export MUST be the last line
module.exports = app;

