# LilianTech 5.0.0 → 6.0.0

## Business and revenue engine
- Added a provider finance ledger using `provider_transactions.publisher_revenue`, `user_reward`, and `margin`.
- Member balances are credited from the member reward, not the provider's gross publisher payout.
- Added configurable reward shares: `REWARD_SHARE`, `CPX_REWARD_SHARE`, and `BITLABS_REWARD_SHARE` (default 0.70).
- Added `/api/admin/revenue` with overall and per-provider revenue, member rewards, margin, validated event count, and pending payout liability.
- Added a Revenue section to the admin dashboard.
- CPX callbacks now record publisher revenue and member reward separately and handle a later CPX reversal without double-crediting.
- BitLabs callbacks now record gross revenue separately from member reward and support reversal/chargeback-style callback states.
- BitLabs survey rewards are not displayed as USD unless a `BITLABS_POINTS_PER_USD` conversion is configured.

## Database reliability
- Reordered initialization so all tables are created before migrations and cleanup queries. Fresh production databases no longer fail because an ALTER/DELETE references a table that has not yet been created.
- Demo/test artifacts are still removed at startup and balances are rebuilt from the remaining transaction ledger.

## Configuration
- Added `BITLABS_POINTS_PER_USD` as a deployment secret/config value. Do not guess the conversion; use the reward conversion configured for the approved BitLabs app.

## Validation
- `node --check server.js` passes.
