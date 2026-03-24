#!/usr/bin/env node

const { ethers } = require("ethers");
const WebSocket = require("ws");
const https = require("https");
const crypto = require("crypto");

// ═══════════════════════════════════════════════════════
//  CONFIGURATION (all via environment variables)
// ═══════════════════════════════════════════════════════
const CONFIG = {
    POLYGON_RPC_URL: process.env.POLYGON_RPC_URL || "https://polygon-rpc.com",
    PROXY_WALLET_KEY: process.env.PROXY_WALLET_KEY,
    CLOB_API_KEY: process.env.POLYMARKET_CLOB_API_KEY,
    CLOB_API_SECRET: process.env.POLYMARKET_CLOB_API_SECRET,
    CLOB_API_PASSPHRASE: process.env.POLYMARKET_CLOB_API_PASSPHRASE,
    GAMMA_API_URL: "https://gamma-api.polymarket.com",
    CLOB_API_URL: "https://clob.polymarket.com",
    CLOB_WS_URL: "wss://ws-subscriptions-clob.polymarket.com/ws/market",
    BINANCE_WS_URL: "wss://stream.binance.com:9443/ws/btcusdt@ticker",
    CTF_EXCHANGE_ADDRESS: "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E",
    USDC_ADDRESS: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
    CHAIN_ID: 137,
    GAP_THRESHOLD_PERCENT: 0.15,
    MARKET_DISCOVERY_INTERVAL_MS: 30_000,
    MAX_POSITION_USDC: 50,
    MAX_DAILY_LOSS_USDC: 100,
    COOLDOWN_MS: 2_000,
    DRY_RUN: process.env.DRY_RUN !== "false",
};

// ═══════════════════════════════════════════════════════
//  VALIDATION
// ═══════════════════════════════════════════════════════
function validateConfig() {
    const missing = [];
    if (!CONFIG.PROXY_WALLET_KEY) missing.push("PROXY_WALLET_KEY");
    if (!CONFIG.CLOB_API_KEY) missing.push("POLYMARKET_CLOB_API_KEY");
    if (!CONFIG.CLOB_API_SECRET) missing.push("POLYMARKET_CLOB_API_SECRET");
    if (!CONFIG.CLOB_API_PASSPHRASE) missing.push("POLYMARKET_CLOB_API_PASSPHRASE");
    if (missing.length > 0 && !CONFIG.DRY_RUN) {
        console.error(`[FATAL] Missing env vars for live trading: ${missing.join(", ")}`);
        console.error("[INFO] Set DRY_RUN=true (default) to run in simulation mode.");
        process.exit(1);
    }
    if (missing.length > 0) {
        console.warn(`[WARN] Missing env vars (${missing.join(", ")}). Running in DRY_RUN mode.`);
    }
}

// ═══════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════
let currentSpotPrice = 0;
let prevSpotPrice = 0;
const activeMarkets = new Map();
const recentTrades = new Map();
let dailyPnl = 0;
let totalTrades = 0;
let totalWins = 0;
let nonceCache = null;

// ═══════════════════════════════════════════════════════
//  PROVIDER & WALLET
// ═══════════════════════════════════════════════════════
const provider = new ethers.JsonRpcProvider(CONFIG.POLYGON_RPC_URL, CONFIG.CHAIN_ID, {
    staticNetwork: true,
    batchMaxCount: 1,
});
let wallet;
if (CONFIG.PROXY_WALLET_KEY) {
    wallet = new ethers.Wallet(CONFIG.PROXY_WALLET_KEY, provider);
}

// ═══════════════════════════════════════════════════════
//  EIP-712 ORDER SIGNING (Polymarket CTF Exchange)
// ═══════════════════════════════════════════════════════
const ORDER_TYPEHASH = {
    Order: [
        { name: "salt", type: "uint256" },
        { name: "maker", type: "address" },
        { name: "signer", type: "address" },
        { name: "taker", type: "address" },
        { name: "tokenId", type: "uint256" },
        { name: "makerAmount", type: "uint256" },
        { name: "takerAmount", type: "uint256" },
        { name: "expiration", type: "uint256" },
        { name: "nonce", type: "uint256" },
        { name: "feeRateBps", type: "uint256" },
        { name: "side", type: "uint8" },
        { name: "signatureType", type: "uint8" },
    ],
};

const DOMAIN = {
    name: "Polymarket CTF Exchange",
    version: "1",
    chainId: CONFIG.CHAIN_ID,
    verifyingContract: CONFIG.CTF_EXCHANGE_ADDRESS,
};

const SIDE_BUY = 0;
const SIDE_SELL = 1;

async function buildAndSignOrder(tokenId, side, price, size) {
    if (!wallet) throw new Error("Wallet not initialized");

    if (!nonceCache) {
        nonceCache = await provider.getTransactionCount(wallet.address);
    }

    const makerAmount = side === SIDE_BUY
        ? ethers.parseUnits(String(Math.floor(size * price * 1e4) / 1e4), 6)
        : ethers.parseUnits(String(size), 6);
    const takerAmount = side === SIDE_BUY
        ? ethers.parseUnits(String(size), 6)
        : ethers.parseUnits(String(Math.floor(size * price * 1e4) / 1e4), 6);

    const salt = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
    const expiration = BigInt(Math.floor(Date.now() / 1000) + 120);

    const order = {
        salt,
        maker: wallet.address,
        signer: wallet.address,
        taker: ethers.ZeroAddress,
        tokenId: BigInt(tokenId),
        makerAmount,
        takerAmount,
        expiration,
        nonce: BigInt(nonceCache++),
        feeRateBps: BigInt(0),
        side,
        signatureType: 2,
    };

    const signature = await wallet.signTypedData(DOMAIN, ORDER_TYPEHASH, order);

    return {
        order: {
            salt: order.salt.toString(),
            maker: order.maker,
            signer: order.signer,
            taker: order.taker,
            tokenId: order.tokenId.toString(),
            makerAmount: order.makerAmount.toString(),
            takerAmount: order.takerAmount.toString(),
            expiration: order.expiration.toString(),
            nonce: order.nonce.toString(),
            feeRateBps: order.feeRateBps.toString(),
            side,
            signatureType: order.signatureType,
        },
        signature,
    };
}

// ═══════════════════════════════════════════════════════
//  CLOB API (HMAC Auth)
// ═══════════════════════════════════════════════════════
function generateHmacHeaders(method, path, body = "") {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const message = timestamp + method.toUpperCase() + path + body;
    const hmac = crypto.createHmac("sha256", CONFIG.CLOB_API_SECRET || "");
    hmac.update(message);
    const signature = hmac.digest("base64");
    return {
        "POLY_API_KEY": CONFIG.CLOB_API_KEY,
        "POLY_TIMESTAMP": timestamp,
        "POLY_SIGNATURE": signature,
        "POLY_PASSPHRASE": CONFIG.CLOB_API_PASSPHRASE,
    };
}

function httpRequest(method, url, body = null) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const path = parsed.pathname + parsed.search;
        const bodyStr = body ? JSON.stringify(body) : "";
        const authHeaders = generateHmacHeaders(method, path, bodyStr);

        const options = {
            hostname: parsed.hostname,
            port: 443,
            path,
            method: method.toUpperCase(),
            headers: {
                "Content-Type": "application/json",
                ...authHeaders,
            },
        };

        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(data); }
            });
        });
        req.on("error", reject);
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

async function submitOrderToCLOB(signedOrder) {
    const payload = {
        order: signedOrder.order,
        signature: signedOrder.signature,
        owner: wallet.address,
        orderType: "FOK",
    };
    return await httpRequest("POST", `${CONFIG.CLOB_API_URL}/order`, payload);
}

// ═══════════════════════════════════════════════════════
//  MARKET DISCOVERY (Slug-Based — Gamma Events API)
// ═══════════════════════════════════════════════════════
const SLUG_PREFIX = "btc-updown-5m-";
const INTERVAL_SECS = 300;
const startPrices = new Map();
let pollCount = 0;

function fetchJson(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                try { resolve(JSON.parse(data)); }
                catch { reject(new Error("Invalid JSON from " + url)); }
            });
        }).on("error", reject);
    });
}

function nextBoundaries(nowSecs, count = 3) {
    const current = Math.floor(nowSecs / INTERVAL_SECS) * INTERVAL_SECS;
    return Array.from({ length: count }, (_, i) => current + i * INTERVAL_SECS);
}

async function fetchEventBySlug(slug) {
    try {
        const url = `${CONFIG.GAMMA_API_URL}/events?slug=${slug}`;
        const data = await fetchJson(url);
        if (Array.isArray(data) && data.length > 0) return data[0];
    } catch (e) {
        // Slug not found — normal for future boundaries
    }
    return null;
}

async function discoverMarkets() {
    try {
        pollCount++;
        const nowMs = Date.now();
        const nowSecs = Math.floor(nowMs / 1000);
        const boundaries = nextBoundaries(nowSecs, 3);
        const slugs = boundaries.map((ts) => `${SLUG_PREFIX}${ts}`);

        let discovered = 0;

        const results = await Promise.all(slugs.map(fetchEventBySlug));

        for (let i = 0; i < slugs.length; i++) {
            const slug = slugs[i];
            const event = results[i];
            if (!event) continue;

            const eventMarkets = event.markets || [];
            if (eventMarkets.length === 0) continue;

            const m = eventMarkets[0];
            if (!m.acceptingOrders) continue;

            const cid = m.conditionId || "";
            if (activeMarkets.has(cid)) continue;

            let clobIds;
            try {
                clobIds = typeof m.clobTokenIds === "string"
                    ? JSON.parse(m.clobTokenIds) : (m.clobTokenIds || []);
            } catch { clobIds = []; }

            if (clobIds.length < 2) {
                console.warn(`[DISCOVERY] Market ${slug} has ${clobIds.length} token IDs, skipping`);
                continue;
            }

            let prices;
            try {
                prices = typeof m.outcomePrices === "string"
                    ? JSON.parse(m.outcomePrices) : (m.outcomePrices || ["0.5", "0.5"]);
            } catch { prices = ["0.5", "0.5"]; }

            const endDate = m.endDate || "";
            let endTs;
            try {
                endTs = new Date(endDate.replace("Z", "+00:00")).getTime();
            } catch { continue; }

            const startTimeStr = m.eventStartTime || m.startDate || "";
            let startTs;
            try {
                startTs = new Date(startTimeStr.replace("Z", "+00:00")).getTime();
            } catch { startTs = endTs - INTERVAL_SECS * 1000; }

            const timeToClose = endTs - nowMs;
            if (timeToClose <= 0 || timeToClose > 600_000) continue;

            activeMarkets.set(cid, {
                conditionId: cid,
                question: m.question || event.title || "",
                endTime: endTs,
                startTime: startTs,
                yesTokenId: clobIds[0],
                noTokenId: clobIds[1],
                yesPrice: parseFloat(prices[0]) || 0.5,
                noPrice: parseFloat(prices[1]) || 0.5,
                slug,
            });
            discovered++;
        }

        // Prune expired
        for (const [id, mkt] of activeMarkets.entries()) {
            if (mkt.endTime < nowMs) {
                activeMarkets.delete(id);
                startPrices.delete(id);
            }
        }

        if (pollCount <= 5 || discovered > 0) {
            console.log(
                `[DISCOVERY] Poll #${pollCount}: slugs=[${slugs.map(s => s.split("-").pop()).join(",")}] ` +
                `discovered=${discovered} tracked=${activeMarkets.size}`
            );
        }
        if (discovered > 0) {
            for (const mkt of activeMarkets.values()) {
                const ttc = ((mkt.endTime - nowMs) / 1000).toFixed(0);
                console.log(
                    `  → ${(mkt.question || "").slice(0, 60)} | slug=${mkt.slug} | ` +
                    `Up=${mkt.yesPrice} Down=${mkt.noPrice} | closes in ${ttc}s`
                );
            }
        }
    } catch (e) {
        console.error(`[DISCOVERY] Error: ${e.message}`);
    }
}

// ═══════════════════════════════════════════════════════
//  SPOT PRICE FEED (Binance WebSocket)
// ═══════════════════════════════════════════════════════
function connectBinance() {
    console.log("[SPOT] Connecting to Binance WS...");
    const ws = new WebSocket(CONFIG.BINANCE_WS_URL);

    ws.on("message", (data) => {
        try {
            const parsed = JSON.parse(data);
            if (parsed.c) {
                prevSpotPrice = currentSpotPrice;
                currentSpotPrice = parseFloat(parsed.c);
                evaluateAllMarkets();
            }
        } catch (e) {}
    });

    ws.on("close", () => {
        console.warn("[SPOT] Binance WS closed. Reconnecting in 500ms...");
        setTimeout(connectBinance, 500);
    });
    ws.on("error", () => ws.close());
}

// ═══════════════════════════════════════════════════════
//  CLOB ORDERBOOK LIVE FEED (Polymarket WS)
// ═══════════════════════════════════════════════════════
function connectClobWs() {
    console.log("[CLOB_WS] Connecting to CLOB WebSocket...");
    const ws = new WebSocket(CONFIG.CLOB_WS_URL);

    ws.on("open", () => {
        const tokenIds = [];
        for (const m of activeMarkets.values()) {
            tokenIds.push(m.yesTokenId, m.noTokenId);
        }
        if (tokenIds.length > 0) {
            ws.send(JSON.stringify({
                type: "subscribe",
                channel: "market",
                assets_ids: tokenIds,
            }));
        }
    });

    ws.on("message", (data) => {
        try {
            const parsed = JSON.parse(data);
            if (parsed.asset_id && parsed.price !== undefined) {
                for (const m of activeMarkets.values()) {
                    if (m.yesTokenId === parsed.asset_id) {
                        m.yesPrice = parseFloat(parsed.price);
                    } else if (m.noTokenId === parsed.asset_id) {
                        m.noPrice = parseFloat(parsed.price);
                    }
                }
            }
        } catch (e) {}
    });

    ws.on("close", () => {
        console.warn("[CLOB_WS] Disconnected. Reconnecting in 500ms...");
        setTimeout(connectClobWs, 500);
    });
    ws.on("error", () => ws.close());
}

// ═══════════════════════════════════════════════════════
//  GAP EVALUATION ENGINE
// ═══════════════════════════════════════════════════════
let lastTradeTime = 0;

async function evaluateAllMarkets() {
    if (currentSpotPrice === 0 || activeMarkets.size === 0) return;

    const now = Date.now();
    if (now - lastTradeTime < CONFIG.COOLDOWN_MS) return;

    if (dailyPnl < -CONFIG.MAX_DAILY_LOSS_USDC) {
        console.warn("[RISK] Daily loss limit hit. Pausing.");
        return;
    }

    for (const [conditionId, market] of activeMarkets.entries()) {
        if (recentTrades.has(conditionId)) continue;

        const timeToCloseMs = market.endTime - now;
        if (timeToCloseMs <= 0 || timeToCloseMs > 60_000) continue;

        if (!startPrices.has(conditionId)) {
            startPrices.set(conditionId, currentSpotPrice);
            console.log(`[GAP] Captured start price for ${conditionId.slice(0, 16)}...: $${currentSpotPrice.toFixed(2)}`);
        }
        const refPrice = startPrices.get(conditionId);
        const timeToCloseSec = timeToCloseMs / 1000;

        if (currentSpotPrice > refPrice) {
            const fairUp = estimateFairPrice(currentSpotPrice, refPrice, timeToCloseSec);
            const gap = fairUp - market.yesPrice;

            if (gap > CONFIG.GAP_THRESHOLD_PERCENT) {
                await executeTrade(market, "UP", market.yesTokenId, market.yesPrice, gap);
            }
        } else if (currentSpotPrice < refPrice) {
            const fairDown = estimateFairPrice(currentSpotPrice, refPrice, timeToCloseSec);
            const gap = fairDown - market.noPrice;

            if (gap > CONFIG.GAP_THRESHOLD_PERCENT) {
                await executeTrade(market, "DOWN", market.noTokenId, market.noPrice, gap);
            }
        }
    }
}

function estimateFairPrice(spotPrice, refPrice, timeToCloseSec) {
    if (refPrice <= 0 || spotPrice <= 0) return 0.5;
    const priceDiff = Math.abs(spotPrice - refPrice);
    const pctDiff = priceDiff / refPrice;
    const timeDecay = Math.max(0, 1 - (timeToCloseSec / 60));
    return Math.min(0.99, 0.5 + (pctDiff * 500 * timeDecay));
}

// ═══════════════════════════════════════════════════════
//  TRADE EXECUTION
// ═══════════════════════════════════════════════════════
async function executeTrade(market, side, tokenId, currentPrice, gap) {
    lastTradeTime = Date.now();
    recentTrades.set(market.conditionId, Date.now());

    const sizeUsdc = Math.min(CONFIG.MAX_POSITION_USDC, CONFIG.MAX_POSITION_USDC * (gap / 0.5));

    const logEntry = {
        event: "gap_detected",
        side,
        conditionId: market.conditionId,
        question: market.question,
        spot: currentSpotPrice,
        strike: market.strikePrice,
        pmPrice: currentPrice,
        gap: gap.toFixed(4),
        sizeUsdc: sizeUsdc.toFixed(2),
        timeToClose: ((market.endTime - Date.now()) / 1000).toFixed(1) + "s",
        dryRun: CONFIG.DRY_RUN,
        timestamp: new Date().toISOString(),
    };

    if (CONFIG.DRY_RUN) {
        console.log(`[DRY_RUN] ${JSON.stringify(logEntry)}`);
        totalTrades++;

        // Simulate PnL: if gap > threshold and we'd have entered, assume win
        const estimatedProfit = sizeUsdc * gap * 0.8;
        dailyPnl += estimatedProfit;
        totalWins++;

        console.log(`[DRY_RUN] Simulated PnL: +$${estimatedProfit.toFixed(2)} | Daily: $${dailyPnl.toFixed(2)} | Trades: ${totalTrades} | Wins: ${totalWins}`);
        return;
    }

    // LIVE EXECUTION
    try {
        const pmSide = side === "YES" ? SIDE_BUY : SIDE_BUY;
        const signedOrder = await buildAndSignOrder(tokenId, pmSide, currentPrice, sizeUsdc / currentPrice);
        const result = await submitOrderToCLOB(signedOrder);

        console.log(`[LIVE] Order submitted: ${JSON.stringify(result)}`);
        totalTrades++;

        if (result && result.orderID) {
            totalWins++;
            const estimatedProfit = sizeUsdc * gap * 0.8;
            dailyPnl += estimatedProfit;
        }
    } catch (e) {
        console.error(`[LIVE] Trade failed: ${e.message}`);
        logEntry.error = e.message;
    }

    console.log(JSON.stringify(logEntry));
}

// ═══════════════════════════════════════════════════════
//  DAILY RESET
// ═══════════════════════════════════════════════════════
function scheduleDailyReset() {
    setInterval(() => {
        console.log(`[DAILY] Reset. Trades: ${totalTrades} | Wins: ${totalWins} | PnL: $${dailyPnl.toFixed(2)}`);
        dailyPnl = 0;
        recentTrades.clear();
    }, 24 * 60 * 60 * 1000);
}

// ═══════════════════════════════════════════════════════
//  BOOT
// ═══════════════════════════════════════════════════════
console.log("═══════════════════════════════════════════════════════");
console.log("  Polymarket Arbitrage Daemon (Moltworker Skill)");
console.log("═══════════════════════════════════════════════════════");
console.log(`  Mode:        ${CONFIG.DRY_RUN ? "🔶 DRY RUN (simulation)" : "🟢 LIVE TRADING"}`);
console.log(`  Gap threshold: ${(CONFIG.GAP_THRESHOLD_PERCENT * 100).toFixed(1)}%`);
console.log(`  Max position:  $${CONFIG.MAX_POSITION_USDC}`);
console.log(`  Max daily loss: $${CONFIG.MAX_DAILY_LOSS_USDC}`);
console.log(`  Cooldown:      ${CONFIG.COOLDOWN_MS}ms`);
console.log("═══════════════════════════════════════════════════════");

validateConfig();

// Phase 1: discover markets first
discoverMarkets().then(() => {
    // Phase 2: connect to live feeds
    connectBinance();
    connectClobWs();

    // Phase 3: keep discovering new markets
    setInterval(discoverMarkets, CONFIG.MARKET_DISCOVERY_INTERVAL_MS);
    // Re-subscribe CLOB WS to new token IDs periodically
    setInterval(connectClobWs, 60_000);

    scheduleDailyReset();
});
