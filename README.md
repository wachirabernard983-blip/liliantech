# LilianTech

LilianTech is a global survey-rewards platform. Approved research partners supply earning opportunities; LilianTech credits members only from verified provider callbacks and tracks the provider's gross revenue separately from the member reward.

## Version
7.0.0

## Production configuration
Required:
- `DATABASE_URL`
- `SESSION_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_NAME`

Survey providers:
- `CPX_APP_ID`
- `CPX_SECURE_HASH`
- `BITLABS_API_TOKEN`
- `BITLABS_APP_SECRET`
- `BITLABS_POINTS_PER_USD` when BitLabs reward points need conversion to USD
- `CINT_JWT`
- `DYNATA_ACCESS_KEY`
- `DYNATA_SECRET_KEY`

Revenue controls:
- `REWARD_SHARE` default `0.70`
- `CPX_REWARD_SHARE` default `0.70`
- `BITLABS_REWARD_SHARE` default `0.70`

Payout providers are credential-gated and are not treated as live until their provider credentials and callback/confirmation flow are configured.

## Revenue model
For a validated provider event:

`provider revenue - member reward = LilianTech margin`

The member wallet receives only the configured member reward. Provider gross revenue is stored separately for the administrator revenue dashboard.

## Important
Never add demo survey inventory or test earnings to production. Never enter guessed provider secrets or payout credentials.


## Version 7
- Added Terms of Service and Privacy Policy pages and footer links.
- Added explicit Terms/Privacy consent to account registration.
- Added TheoremReach server-side reward callback with HMAC-SHA1 verification, duplicate transaction protection and reversals.
- Added configurable TheoremReach entry URL and exchange rate.
- Official support contact: support@liliantech.online.

TheoremReach configuration:
- `THEOREMREACH_API_KEY` (stored server-side for future/approved API flows)
- `THEOREMREACH_SECRET_KEY`
- `THEOREMREACH_ENTRY_URL`
- `THEOREMREACH_EXCHANGE_RATE` (default 100)
