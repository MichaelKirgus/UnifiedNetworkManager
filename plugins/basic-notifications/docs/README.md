# Basic Notification Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A stateless **notification transport**:
it delivers already-rendered UNM notifications over the three most common
easy-to-implement channels. The API owns rules, channels and templates — this
plugin only sends one title + body per channel type.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Notification sender (`notificationSender`) | — | Stateless delivery service; no devices of its own. |

## Channels

| Channel | How it works | Credentials |
| --- | --- | --- |
| Email (SMTP) | Plain-text email through any SMTP server (`starttls`, `implicit` or `none`). | Optional bound *Username / Password* secret (auth is skipped when absent). |
| Webhook (HTTP) | POST/PUT the message as JSON or plain text to any endpoint. | Optional bound *API Key (without secret)* → sent as a Bearer header. |
| Telegram (Bot) | Telegram Bot API `sendMessage` to a chat. | Bound *API Key (without secret)* holding the bot token. |

## Metrics

- `notify.total` — notifications sent (lifetime counter).
- `notify.failuresTotal` — failed deliveries (lifetime counter).

Both are also surfaced via self-metrics for plugin health monitoring.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `NOTIFY_SEND_TIMEOUT_MS` | `12000` | Per-send timeout; kept below the API's `/notify` timeout so failures surface as plugin errors. |
| `PORT` / `ADVERTISED_ENDPOINT` / `UNM_API_URL` / `PLUGIN_API_KEY` | — | Standard UNM plugin wiring. |

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
