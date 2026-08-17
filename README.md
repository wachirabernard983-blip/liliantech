# LilianTech

LilianTech is a global survey-rewards platform. Approved research partners supply earning opportunities; LilianTech credits members only from verified provider callbacks and tracks the provider's gross revenue separately from the member reward.

## Version
7.0.0

## Production configuration

Email verification uses the Resend HTTPS API when `RESEND_API_KEY` is present. `NOTIFICATION_FROM` should use a sender address verified in Resend (recommended: `LilianTech <support@liliantech.online>`). SMTP remains a fallback.

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
- `THEOREMREACH_ENTRY_URL` (legacy hosted entry; no longer used by the LilianTech survey wall)
- `THEOREMREACH_SURVEYS_API_URL` (set only to the exact native Surveys API endpoint supplied/approved by TheoremReach; may use `{api_key}`, `{user_id}`, `{ip}` tokens)
- `THEOREMREACH_EXCHANGE_RATE` (default 100)


## v12 survey and notification changes
- Surveys are 10-question bundles submitted together.
- Surveys use globally shared response limits via `SURVEY_MAX_RESPONSES` (default 100).
- New/closed surveys are pushed to connected dashboards through SSE.
- Email notifications use SMTP environment variables.
- Browser push notifications use VAPID environment variables and `/sw.js`.
- Set `VAPID_PUBLIC_KEY` and `VAPID_PRIVATE_KEY` in Render for push.


## v15 changes
- $0.001 per question; $0.010 per completed 10-question survey.
- Members receive exactly five active surveys at a time. A new five-survey batch is generated after the member completes all five, without waiting for the global 1,000-response cap.
- Survey inventory refreshes every 30 minutes, with an immediate refresh after submission.
- New-batch notifications can target the member who unlocked the batch.


## v7.2 account and navigation polish

- Added password reset by email with a 6-digit recovery code.
- Added show/hide password controls to sign-in and password creation/reset forms.
- Standardized authentication pages, spacing, labels, buttons and navigation.
- Improved dashboard header alignment so LilianTech stays at the far left and the member email/logout controls stay at the far right.
- Added lightweight page-entry motion and consistent mobile navigation behavior.
