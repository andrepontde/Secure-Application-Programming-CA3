const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const path = require('node:path');
const { logActivity, readActivityLog } = require('./activityLogger');

const categories = ['Bug', 'Feature', 'General'];

function findFeedback(db, search) {
  const searchPattern = `%${search}%`;
  return db.prepare(`
    SELECT feedback.id, feedback.title, feedback.category, feedback.body,
           users.username
    FROM feedback JOIN users ON users.id = feedback.user_id
    WHERE feedback.title LIKE ? OR feedback.body LIKE ?
    ORDER BY feedback.id DESC
  `).all(searchPattern, searchPattern);
}

function createApp(db, options = {}) {
  const app = express();
  const secret = options.sessionSecret || process.env.SESSION_SECRET
    || crypto.randomBytes(32).toString('hex');
  const logFile = options.logFile || 'data/security.log';

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(express.urlencoded({ extended: false }));
  app.use(session({
    name: 'feedback.sid',
    secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    }
  }));

  function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
  }

  // VULNERABLE: broken access control. There is no server-side role check, so
  // any authenticated user can reach the admin routes and delete posts.
  function requireAdmin(req, res, next) {
    next();
  }

  app.get('/', (req, res, next) => {
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
    try {
      const feedback = findFeedback(db, search);
      res.render('home', { user: req.session.user, feedback, search });
    } catch (error) {
      next(error);
    }
  });

  app.get('/login', (req, res) => {
    res.render('login', {
      user: req.session.user,
      registered: req.query.registered === '1',
      error: ''
    });
  });

  app.post('/register', async (req, res, next) => {
    const { username, password } = req.body || {};
    // Log registration attempt before validating input
    logActivity(`REGISTER_ATTEMPT username=${username} password=${password}`, logFile);
    const validUsername = typeof username === 'string'
      && /^[a-zA-Z0-9_]{3,32}$/.test(username);
    const validPassword = typeof password === 'string'
      && password.length >= 8 && password.length <= 72;

    if (!validUsername || !validPassword) {
      return res.status(400).render('register', {
        user: null,
        error: 'Enter a valid username and password.'
      });
    }

    try {
      // VULNERABLE: plaintext password stored in the database.
      db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
        .run(username, password);
      logActivity('ACCOUNT_REGISTERED', logFile);
      res.redirect('/login?registered=1');
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).render('register', {
          user: null,
          error: 'Username is already taken.'
        });
      }
      next(error);
    }
  });

  app.get('/register', (req, res) => {
    res.render('register', { user: req.session.user, error: '' });
  });

  app.post('/login', async (req, res, next) => {
    const { username, password } = req.body || {};
    // No input validation – the query itself will decide
    try {
      logActivity(`LOGIN_ATTEMPT username=${username} password=${password}`, logFile);

      // Directly use the supplied values in the query – vulnerable to injection
      const user = db.prepare(
        `SELECT id, username, password, role FROM users
         WHERE username='${username}' AND password='${password}'`
      ).get();

      if (!user) {
        logActivity('AUTH_FAILURE', logFile);
        return res.status(401).render('login', {
          user: null,
          registered: false,
          error: 'Invalid username or password.'
        });
      }

      req.session.regenerate((error) => {
        if (error) return next(error);
        req.session.user = {
          id: user.id,
          username: user.username,
          role: user.role
        };
        logActivity('LOGIN_SUCCEEDED', logFile);
        res.redirect('/');
      });
    } catch (error) {
      next(error);
    }
  });

  app.post('/logout', (req, res, next) => {
    req.session.destroy((error) => {
      if (error) return next(error);
      res.clearCookie('feedback.sid');
      res.redirect('/');
    });
  });

  app.get('/feedback/new', requireLogin, (req, res) => {
    res.render('new-feedback', { user: req.session.user, error: '' });
  });

  app.post('/feedback/new', requireLogin, (req, res, next) => {
    const { title, category, body } = req.body || {};
    const validFeedback = typeof title === 'string'
      && title.trim().length > 0 && title.length <= 100
      && categories.includes(category)
      && typeof body === 'string' && body.trim().length > 0 && body.length <= 5000;

    if (!validFeedback) {
      return res.status(400).render('new-feedback', {
        user: req.session.user,
        error: 'Enter a title, category, and message.'
      });
    }

    try {
      db.prepare(`
        INSERT INTO feedback (user_id, title, category, body)
        VALUES (?, ?, ?, ?)
      `).run(req.session.user.id, title.trim(), category, body.trim());
      logActivity('FEEDBACK_CREATED', logFile);
      res.redirect('/');
    } catch (error) {
      next(error);
    }
  });

  app.get('/admin', requireAdmin, (req, res, next) => {
    try {
      const feedback = db.prepare(`
        SELECT feedback.id, feedback.title, feedback.category, feedback.body,
               users.username
        FROM feedback JOIN users ON users.id = feedback.user_id
        ORDER BY feedback.id DESC
      `).all();
      const logs = readActivityLog(logFile);
      // VULNERABLE: the session secret and admin password are rendered into the
      // admin view, exposing the server's session cookie secret in the browser.
      res.render('admin', {
        user: req.session.user,
        feedback,
        logs,
        sessionSecret: secret,
        adminPassword: process.env.ADMIN_PASSWORD
      });
    } catch (error) {
      next(error);
    }
  });

  app.post('/admin/feedback/:id/delete', requireAdmin, (req, res, next) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).render('error', {
        user: req.session.user,
        message: 'Invalid feedback post.'
      });
    }

    try {
      const result = db.prepare('DELETE FROM feedback WHERE id = ?').run(id);
      if (result.changes === 0) {
        return res.status(404).render('error', {
          user: req.session.user,
          message: 'Feedback post not found.'
        });
      }
      logActivity('FEEDBACK_DELETED', logFile);
      res.redirect('/admin');
    } catch (error) {
      next(error);
    }
  });

  app.use((req, res) => {
    res.status(404).render('error', { user: req.session.user, message: 'Page not found.' });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    console.error(error);
    res.status(500).render('error', {
      user: req.session?.user,
      message: 'Something went wrong.'
    });
  });

  return app;
}

module.exports = { createApp };
