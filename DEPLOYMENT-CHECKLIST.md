# Final LilianTech notification deployment

1. Add the environment variables from RENDER-NOTIFICATION-ENV.txt to Render.
2. Put the Resend API key in SMTP_PASS.
3. Put the generated VAPID public key in VAPID_PUBLIC_KEY.
4. Put the generated VAPID private key in VAPID_PRIVATE_KEY.
5. Redeploy the service.
6. Test a new registration:
   Create account -> receive 6-digit email code -> verify -> sign in.
7. In the member profile, enable push notifications.
8. Confirm browser notification permission is granted.
9. Trigger a new survey batch and verify:
   - email notification
   - browser/PWA push notification
10. Keep the VAPID pair unchanged after deployment.
