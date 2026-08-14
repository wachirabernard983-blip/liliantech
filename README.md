# LilianTech

Clean MVP for the LilianTech survey and rewards platform.

## Structure

- `data/` = demo survey/provider data
- `public/` = website files
- `server.js` = Express server, authentication and API
- `package.json` = Node dependencies
- `render.yaml` = Render deployment configuration

## Authentication

LilianTech uses:

- PostgreSQL for user accounts
- `express-session` for server-side login sessions
- `connect-pg-simple` for storing sessions in PostgreSQL
- HTTP-only cookies so the browser does not store the logged-in user in `sessionStorage`

## Render environment variable

Set this environment variable in Render:

`SESSION_SECRET`

Use a long random value. Do not put the secret in GitHub.

`DATABASE_URL` should continue to point to your PostgreSQL database.

## Render build

```text
npm install
```

## Render start

```text
npm start
```


## Authentication deployment

Set these Render environment variables:

- `DATABASE_URL` — your PostgreSQL connection string
- `SESSION_SECRET` — a long random secret

After deployment, test this flow:

1. Create an account.
2. Log in.
3. Confirm you are sent to `/dashboard.html`, not `/`.
4. Refresh the dashboard. Your account should remain signed in.
5. Open `/` and confirm the navigation shows `Dashboard`.
6. Log out and confirm the session is removed.


### Session/navigation fix
Application pages are served with no-cache headers and the session cookie is scoped to `/` so moving between Home and Dashboard does not create a new anonymous session. The homepage checks `/api/me` without cache.
