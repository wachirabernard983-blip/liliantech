# LilianTech dashboard recovery and survey scheduler fix

This build is based on the last known working admin-enabled build (v4), not the broken dashboard/survey build.

Changes:
- Dashboard sidebar label is `Admin`.
- Removed Withdrawals from the member dashboard.
- Removed payout fields from the member Profile form.
- Changed the dashboard action to `View earnings`.
- Aligned the LilianTech brand to the far-left of the dashboard header.
- Preserved the existing admin authorization for the three designated admin emails.
- Preserved the admin users, completed surveys and earnings endpoints.
- Fixed the AI question-generation request role bug that could prevent generation.
- Added an unused-question inventory check so future survey batches can replenish AI questions instead of finding only questions already used in previous campaigns.
- Kept the server-side scheduler running every minute; due batches are released after the 30-minute cooldown even when the user is offline.
- Preserved the survey detail helper functions that were accidentally removed in the previous build.
