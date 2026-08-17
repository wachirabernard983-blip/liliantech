# LilianTech Email Verification & Notifications

Implemented in this build:
- Six-digit email verification during registration.
- Verification codes expire after 10 minutes.
- Maximum five incorrect attempts before a new code is required.
- Resend verification code.
- Login is blocked until new accounts verify their email.
- Existing accounts are treated as verified during the rollout.
- Email survey notifications are sent only to verified users who keep email notifications enabled.
- Web Push subscription endpoints and VAPID configuration.
- Push notifications for newly released surveys.
- Explicit “Enable push notifications” control instead of requesting permission on every dashboard load.
- Notification preferences in the member Profile section.
- PWA manifest and service-worker notification handling.
- Native Android FCM is intentionally not claimed by this web build; it requires the Android project/token registration.
