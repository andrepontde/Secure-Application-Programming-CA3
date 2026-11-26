# Mini Feedback Board

A Node.js, Express, EJS, and SQLite feedback board. Visitors can register and
view/search feedback; signed-in users can post feedback; administrators can
moderate posts and review security logs.

## Requirements and setup

- Node.js 20 or newer and npm
- Git

The application is implemented on the comparison branches. Clone the
repository, then switch to a branch and install its dependencies:

```sh
git clone https://github.com/andrepontde/Secure-Application-Programming-CA3.git
cd Secure-Application-Programming-CA3
git switch secure       # secure implementation
# or: git switch insecure
npm install
cp .env.example .env
npm start
```

Set `SESSION_SECRET` in `.env`; set `ADMIN_USERNAME` and `ADMIN_PASSWORD` to
create the initial administrator. The app listens on port 3000 by default and
creates its SQLite database under `data/`. Run automated tests with `npm test`.
Use only synthetic credentials with the insecure version.

## Comparison branches

- [Secure implementation](https://github.com/andrepontde/Secure-Application-Programming-CA3/tree/Secure)
- [Insecure implementation](https://github.com/andrepontde/Secure-Application-Programming-CA3/tree/Insecure)
