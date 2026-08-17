# LilianTech Email Verification + Survey Notifications

## Required Render environment variables

SMTP:
- `SMTP_HOST`
- `SMTP_PORT` (usually 587)
- `SMTP_SECURE` (`false` for STARTTLS/587; `true` for SSL/465)
- `SMTP_USER`
- `SMTP_PASS`
- `NOTIFICATION_FROM` (for example `support@liliantech.online`)
- `NOTIFICATION_EMAIL_ENABLED=true`

Web Push:
- `NOTIFICATION_PUSH_ENABLED=true`
- `VAPID_PUBLIC_KEY`
- `VAPID_PRIVATE_KEY`
- `VAPID_SUBJECT` (for example `mailto:support@liliantech.online`)

Generate VAPID keys once with:
`npx web-push generate-vapid-keys`

## Registration flow

1. User submits registration.
2. Account is created as unverified.
3. A 6-digit code is emailed.
4. Code expires after 10 minutes.
5. Five incorrect attempts require a new code.
6. Verification signs the user in and opens the dashboard.
7. Existing accounts from before this rollout are automatically treated as verified.

## Survey notifications

When a new survey batch is released for a user:
- Email is sent if email notifications are enabled and the address is verified.
- Web Push is sent to registered browser/PWA subscriptions.
- Clicking the push notification opens the Surveys area.

Push permission is requested only after the member explicitly clicks **Enable push notifications**, which follows modern browser privacy/permission practices.

## Native Android app

This code implements browser/PWA push notifications. A separate native Android build needs Firebase Cloud Messaging (FCM) integration to receive native push notifications. The same backend can be extended with FCM tokens without changing the survey release logic.
