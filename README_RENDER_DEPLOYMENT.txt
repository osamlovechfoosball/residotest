RESIDO - GITHUB + RENDER DEPLOYMENT

Upload this folder to GitHub. Do not upload node_modules or real .env secret files.

Render Web Service settings:
- Service Type: Web Service
- Environment: Node
- Build Command: npm ci --omit=dev
- Start Command: npm start
- Health Check Path: /healthz
- Root Directory: leave empty if server.js, index.html, and package.json are in the repository root.

Production database:
- Use Render PostgreSQL.
- Copy the PostgreSQL Internal Database URL into the Web Service environment as DATABASE_URL.
- server.js automatically creates the needed PostgreSQL tables when DATABASE_URL exists.
- resido-schema.sql is included for manual database review/import.

Required production environment variables in Render:
- NODE_ENV=production
- DATABASE_URL or POSTGRES_URL
- AUTH_SECRET, at least 32 characters
- FRONTEND_ORIGIN, your HTTPS domain
- PUBLIC_APP_URL, your HTTPS domain
- SUPER_ADMIN_EMAIL
- SUPER_ADMIN_PASSWORD
- SUPER_ADMIN_NAME
- Email configuration: RESEND_API_KEY + MAIL_FROM + MAIL_REPLY_TO/SUPPORT_EMAIL
- Stripe configuration: STRIPE_SECRET_KEY + STRIPE_WEBHOOK_SECRET

Email through HTTPS API, not Gmail SMTP:
- This version sends transactional emails through the Resend HTTPS Email API.
- It does not require Gmail SMTP ports 465/587, so it works on Render Free Web Services.
- In Resend, create an API key and add it in Render as RESEND_API_KEY.
- For quick testing, MAIL_FROM can be "Resido" <onboarding@resend.dev>.
- For production, verify residoco.com in Resend DNS and use a sender such as "Resido" <support@residoco.com>.
- Password reset, email-change confirmation, and new-user welcome emails use this same HTTPS sender.

Stripe:
- Webhook endpoint: https://yourdomain.com/stripe/webhook
- Keep ALLOW_DEMO_CARD_PAYMENTS=false for production.
- If STRIPE_REQUIRE_CONNECT=true, each building needs its Stripe connected account ID for resident building-fee payouts.
- When PASS_CARD_FEES_TO_RESIDENT=true, the online payment fee is shown before the user/admin pays and is itemized separately in Stripe Checkout.

Porkbun:
- Porkbun points your domain to Render.
- App login, database, payments, and email API keys are configured in Render and Stripe.
- If you send from support@residoco.com via Resend, add the Resend DNS records in Porkbun exactly as Resend gives them.
