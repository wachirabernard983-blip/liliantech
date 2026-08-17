# Email-first registration

Registration now follows this order:

1. Full name + email + Terms/Privacy consent.
2. LilianTech immediately generates and sends a 6-digit email verification code.
3. User enters the code.
4. Only after the code is successfully verified does LilianTech ask for a password.
5. Password is saved and the account is created/logged in.
6. The verification code never appears after the password step.

Pending registrations are stored separately from `users`, so an unverified person
does not become a normal account until their email is verified.

Required Render email variables:
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=resend
SMTP_PASS=<Resend API key>
NOTIFICATION_FROM=LilianTech <support@liliantech.online>
NOTIFICATION_EMAIL_ENABLED=true
