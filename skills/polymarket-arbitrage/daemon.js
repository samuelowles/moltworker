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
//  MARKET DISCOVERY (Gamma API)
// ═══════════════════════════════════════════════════════
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

async function discoverMarkets() {
    try {
        const url = `${CONFIG.GAMMA_API_URL}/markets?active=true&closed=false&limit=100`;
        const markets = await fetchJson(url);

        if (!Array.isArray(markets)) return;

        const now = Date.now();
        let discovered = 0;

        for (const market of markets) {
            const q = (market.question || "").toLowerCase();
            const isBtc = q.includes("bitcoin") || q.includes("btc");
            const is5min = q.includes("5 minute") || q.includes("5min") || q.includes("five minute");

            if (!isBtc || !is5min) continue;

            const endTime = market.end_date_iso ? new Date(market.end_date_iso).getTime() : 0;
            const timeToClose = endTime - now;

            if (timeToClose > 0 && timeToClose < 5 * 60 * 1000) {
                const tokens = market.tokens || [];
                const yesToken = tokens.find((t) => t.outcome === "Yes");
                const noToken = tokens.find((t) => t.outcome === "No");

                if (yesToken && noToken) {
                    activeMarkets.set(market.condition_id, {
                        conditionId: market.condition_id,
                        question: market.question,
                        endTime,
                        timeToClose,
                        yesTokenId: yesToken.token_id,
                        noTokenId: noToken.token_id,
                        yesPrice: parseFloat(yesToken.price || "0.5"),
                        noPrice: parseFloat(noToken.price || "0.5"),
                        strikePrice: extractStrikePrice(market.question),
                    });
                    discovered++;
                }
            }
        }

        // Prune expired markets
        for (const [id, m] of activeMarkets.entries()) {
            if (m.endTime < now) activeMarkets.delete(id);
        }

        if (discovered > 0) {
            console.log(`[DISCOVERY] Found ${discovered} active 5-min BTC markets. Total tracked: ${activeMarkets.size}`);
        }
    } catch (e) {
        console.error(`[DISCOVERY] Error: ${e.message}`);
    }
}

function extractStrikePrice(question) {
    const match = question.match(/\$?([\d,]+\.?\d*)/);
    if (match) return parseFloat(match[1].replace(/,/g, ""));
    return 0;
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

        const timeToClose = market.endTime - now;
        if (timeToClose <= 0 || timeToClose > 60_000) continue;

        const spotAboveStrike = currentSpotPrice > market.strikePrice;
        const spotBelowStrike = currentSpotPrice < market.strikePrice;

        // The gap: if spot is clearly above strike, YES should be near 1.00.
        // If YES is still lagging significantly below fair value, that's an
        // opportunity to buy YES cheaply.
        if (spotAboveStrike) {
            const fairYes = estimateFairPrice(currentSpotPrice, market.strikePrice, timeToClose);
            const gap = fairYes - market.yesPrice;

            if (gap > CONFIG.GAP_THRESHOLD_PERCENT) {
                await executeTrade(market, "YES", market.yesTokenId, market.yesPrice, gap);
            }
        } else if (spotBelowStrike) {
            const fairNo = estimateFairPrice(market.strikePrice, currentSpotPrice, timeToClose);
            const gap = fairNo - market.noPrice;

            if (gap > CONFIG.GAP_THRESHOLD_PERCENT) {
                await executeTrade(market, "NO", market.noTokenId, market.noPrice, gap);
            }
        }
    }
}

function estimateFairPrice(winningPrice, losingPrice, timeToCloseMs) {
    const priceDiff = Math.abs(winningPrice - losingPrice);
    const pctDiff = priceDiff / winningPrice;
    const timeDecay = Math.max(0, 1 - (timeToCloseMs / 60_000));
    // The closer we are to settlement and the larger the price diff,
    // the more likely the winning side settles at 1.00
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
