# LilianTech — Survey & Rewards Platform

This build preserves the working authentication/session behavior and adds the main member and admin modules in one pass.

## Included

- Server-side PostgreSQL sessions
- Registration/login/logout
- Dashboard overview
- Available/in-progress/completed surveys
- Provider survey inventory import layer
- Earnings ledger
- Withdrawal requests and withdrawal history
- Minimum withdrawal configuration
- Profile and payout settings
- Admin overview
- User management view
- Withdrawal approval/rejection/payment workflow
- Provider survey inventory management
- Production health endpoint
- Render deployment configuration

## Important: real survey providers

There is no local/demo survey inventory. LilianTech displays survey opportunities only from approved provider integrations using the provider's approved API/offerwall credentials, callback rules and commercial terms. Do not invent provider credentials or scrape provider inventory.

## Production environment

Set:

- `DATABASE_URL` — PostgreSQL connection string
- `SESSION_SECRET` — long random secret (Render can generate it)
- `ADMIN_EMAIL` — the single designated administrator email (default `wachirabernard193@gmail.com`)
- `MIN_WITHDRAWAL` — minimum withdrawal amount, default 25

## Deployment

The included `render.yaml` is configured for a Node web service. After deployment, attach your custom domain in the hosting provider and point the domain's DNS records to the host as instructed by that provider.

Before going live, verify HTTPS, PostgreSQL, session persistence, email delivery, provider approval/credentials, payout provider compliance, privacy policy, terms, and applicable legal requirements.


## Production requirements
- Minimum withdrawal defaults to $25 and is configurable with `MIN_WITHDRAWAL`.
- Admin access is restricted server-side to `ADMIN_NAME=Bernard Wachira` and `ADMIN_EMAIL=wachirabernard193@gmail.com`.
- Live CPX/BitLabs surveys open in the LilianTech in-app survey player first; a new-tab fallback is provided if the provider blocks embedding.
- Provider rewards are credited only from verified provider callbacks; there are no local/demo reward sources.
- Cint and Dynata remain credential-gated until their publisher approvals and credentials are supplied.


## Production safety changes in this build

- Only the designated administrator identity (`Bernard Wachira` + `wachirabernard193@gmail.com`) can receive the admin role or open `/admin.html`.
- Ordinary members cannot reveal the admin page by typing its URL directly.
- No local/demo surveys are included in the project.
- Manual provider-survey imports are not exposed as live member inventory until the approved provider click/callback integration exists.
- Member-side manual survey completion cannot create real-money rewards in production.
- CPX inventory requests are gated until the CPX secure hash is configured and are cached for no more than 120 seconds, matching CPX's API guidance.
- BitLabs requests include the per-user `X-User-Id` header, and reward callbacks remain disabled until the BitLabs app secret is configured and the callback is verified.
- Withdrawal requests reserve funds while pending or approved, preventing a user from submitting multiple requests against the same available balance.
- Withdrawal state transitions are enforced server-side: pending → approved/rejected → paid.
- Authentication endpoints have a basic IP-based rate limit.


## Version 2 payout setup

Version 2 adds a real withdrawal workflow with method-specific fields. Automatic payout is credential-gated: without provider credentials, a withdrawal is safely queued instead of pretending it was paid.




### PayPal automatic payouts
Configure only after creating an appropriate PayPal developer/business payout setup:

- `PAYPAL_ENV` = `sandbox` or `live`
- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `PAYPAL_SENDER_EMAIL`

### Other methods
Bank transfer is currently a secure queued/manual method. It collects account holder name, bank name, account number and branch/SWIFT information. It does not claim automatic settlement until a bank/payment provider integration is actually configured.

### Important
Never place payout credentials in the frontend. Never mark a payout as paid merely because a request was submitted. Provider confirmation or administrator verification must finalize the ledger debit.
