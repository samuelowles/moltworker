---
name: polymarket-arbitrage
description: Background daemon that exploits 5-minute BTC prediction market gaps on Polymarket via the CLOB API.
---

# Polymarket Arbitrage Daemon

Background process that replicates the "Clawbot" strategy: monitoring thousands of 5-minute BTC prediction markets on Polymarket and executing millisecond trades when the contract price lags behind Binance spot.

## Required Environment Variables

| Variable | Description | Where to Get It |
|---|---|---|
| `PROXY_WALLET_KEY` | Private key for the Polygon wallet with USDC and Polymarket proxy wallet approval | Your own Ethereum-compatible wallet |
| `POLYMARKET_CLOB_API_KEY` | API key for the Polymarket CLOB | [Polymarket CLOB API](https://docs.polymarket.com/#create-api-key) — generated via a signed message from your wallet |
| `POLYMARKET_CLOB_API_SECRET` | HMAC secret paired with the API key | Generated alongside the API key |
| `POLYMARKET_CLOB_API_PASSPHRASE` | Passphrase paired with the API key | Generated alongside the API key |
| `POLYGON_RPC_URL` | A fast Polygon RPC endpoint | [Alchemy](https://www.alchemy.com/), [QuickNode](https://www.quicknode.com/), or [Infura](https://infura.io/) |
| `DRY_RUN` | Set to `"false"` for live trading. Default is `"true"` (simulation) | N/A |

## Architecture

```
Binance WS ──► Spot Price ──┐
                             ├──► Gap Engine ──► EIP-712 Signer ──► CLOB POST /order
Gamma API  ──► Market List ──┤
CLOB WS    ──► Live Prices ──┘
```

- **Market Discovery**: Polls `gamma-api.polymarket.com/markets` every 30s. Filters for active, open, 5-minute BTC markets closing within 5 minutes.
- **Spot Feed**: Binance `btcusdt@ticker` WebSocket with 500ms auto-reconnect.
- **CLOB Feed**: Live orderbook prices via `ws-subscriptions-clob.polymarket.com`.
- **Gap Signal**: Compares spot direction against contract probability. If spot is clearly above strike but YES is lagging, the daemon buys YES (and vice versa for NO).
- **Execution**: Constructs a valid EIP-712 signed CTF Exchange order and submits it as a Fill-Or-Kill order to `clob.polymarket.com/order`.

## Risk Controls

- Max $50 position per trade
- Max $100 daily loss circuit breaker
- 2-second cooldown between trades
- Per-market deduplication (one trade per condition ID)
- Daily PnL reset with logging

## Execution

```bash
# Dry run (default)
node /root/clawd/skills/polymarket-arbitrage/daemon.js

# Live trading
DRY_RUN=false node /root/clawd/skills/polymarket-arbitrage/daemon.js
```
