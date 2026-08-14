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

The demo surveys remain available for testing. Provider survey inventory can be imported from approved providers through the admin panel. A real CPX/BitLabs/Cint integration must use the provider's approved API/offerwall credentials, callback rules and commercial terms. Do not invent provider credentials or scrape their inventory.

## Production environment

Set:

- `DATABASE_URL` — PostgreSQL connection string
- `SESSION_SECRET` — long random secret (Render can generate it)
- `ADMIN_EMAILS` — comma-separated email addresses that should receive the admin role during startup
- `MIN_WITHDRAWAL` — minimum withdrawal amount, default 10

## Deployment

The included `render.yaml` is configured for a Node web service. After deployment, attach your custom domain in the hosting provider and point the domain's DNS records to the host as instructed by that provider.

Before going live, verify HTTPS, PostgreSQL, session persistence, email delivery, provider approval/credentials, payout provider compliance, privacy policy, terms, and applicable legal requirements.


## Production requirements
- Minimum withdrawal defaults to $25 and is configurable with `MIN_WITHDRAWAL`.
- Admin access is restricted server-side to `ADMIN_NAME=Bernard Wachira` and `ADMIN_EMAIL=wachirabernard193@gmail.com`.
- Live CPX/BitLabs surveys open in the LilianTech in-app survey player first; a new-tab fallback is provided if the provider blocks embedding.
- Provider rewards are credited only from verified provider callbacks; demo/local surveys are not production reward sources.
- Cint and Dynata remain credential-gated until their publisher approvals and credentials are supplied.
