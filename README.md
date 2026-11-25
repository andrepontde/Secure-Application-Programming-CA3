# Mini Feedback Board

## Run

Requires Node.js 20 or newer.

```sh
npm install
cp .env.example .env
npm start
```

Edit `.env` before starting. The app runs at `http://localhost:3000` and creates
`data/feedback.db` automatically.

Set `SESSION_SECRET` to a private random value. Set `PORT` to change the port.
To create an administrator when the database is first initialized, set
`ADMIN_USERNAME` and `ADMIN_PASSWORD` (at least 12 characters).

## Branches

- `main` contains the shared baseline.
- `insecure` is created from `main` for the insecure comparison.
- `secure` is created from `insecure` to show the security changes.

Keep the insecure implementation out of `main`.

## Routes

| Method | Route | Use |
|---|---|---|
| `GET` | `/` | View or search the feedback board |
| `GET` | `/login` | Show the login page |
| `GET` | `/register` | Show the registration page |
| `GET` | `/feedback/new` | Show the feedback form (login required) |
| `GET` | `/admin` | View and delete posts, and review recent security events (admin only) |
| `POST` | `/register` | Create an account |
| `POST` | `/login` | Log in |
| `POST` | `/logout` | Log out |
| `POST` | `/feedback/new` | Submit feedback (login required) |
| `POST` | `/admin/feedback/:id/delete` | Delete a post from the admin page |
