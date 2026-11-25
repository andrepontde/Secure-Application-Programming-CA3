require('dotenv').config();

const path = require('node:path');
const { createDatabase } = require('./database');
const { createApp } = require('./app');

const adminCredentials = process.env.ADMIN_USERNAME || process.env.ADMIN_PASSWORD
  ? { username: process.env.ADMIN_USERNAME, password: process.env.ADMIN_PASSWORD }
  : undefined;
const db = createDatabase(path.join(process.cwd(), 'data', 'feedback.db'), adminCredentials);
const app = createApp(db);
const port = Number(process.env.PORT) || 3000;

const server = app.listen(port, () => {
  console.log(`Feedback API listening on http://localhost:${port}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
