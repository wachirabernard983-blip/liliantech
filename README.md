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
