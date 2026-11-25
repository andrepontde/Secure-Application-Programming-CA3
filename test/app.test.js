const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createApp } = require('../src/app');
const { createDatabase } = require('../src/database');

async function startTestApp(t, { admin = false } = {}) {
  const logFolder = fs.mkdtempSync(path.join(os.tmpdir(), 'feedback-test-'));
  const logFile = path.join(logFolder, 'security.log');
  const adminCredentials = admin
    ? { username: 'test_admin', password: 'a-long-admin-password' }
    : undefined;
  const db = createDatabase(':memory:', adminCredentials);
  const app = createApp(db, {
    sessionSecret: 'test-secret-that-is-long-enough',
    logFile
  });
  const server = app.listen(0);

  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  let databaseClosed = false;
  function closeDatabase() {
    if (!databaseClosed) {
      db.close();
      databaseClosed = true;
    }
  }

  t.after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    closeDatabase();
    fs.rmSync(logFolder, { recursive: true, force: true });
  });

  return {
    closeDatabase,
    db,
    logFile,
    url: `http://127.0.0.1:${server.address().port}`
  };
}

async function postForm(url, route, fields, cookie) {
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (cookie) headers.cookie = cookie;

  return fetch(`${url}${route}`, {
    method: 'POST',
    headers,
    body: new URLSearchParams(fields),
    redirect: 'manual'
  });
}

async function registerAndLogin(url, username = 'board_user') {
  const password = 'a-strong-password';
  const register = await postForm(url, '/register', { username, password });
  assert.equal(register.status, 302);

  const login = await postForm(url, '/login', { username, password });
  assert.equal(login.status, 302);
  return login.headers.get('set-cookie').split(';')[0];
}

test('UC-1 and UC-2: a registered user logs in and submits feedback', async (t) => {
  const { db, logFile, url } = await startTestApp(t);

  const protectedPage = await fetch(`${url}/feedback/new`, { redirect: 'manual' });
  assert.equal(protectedPage.status, 302);
  assert.equal(protectedPage.headers.get('location'), '/login');

  const unauthenticatedPost = await postForm(url, '/feedback/new', {
    title: 'Unauthenticated post',
    category: 'General',
    body: 'This must not be stored.'
  });
  assert.equal(unauthenticatedPost.status, 302);
  assert.equal(unauthenticatedPost.headers.get('location'), '/login');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM feedback').get().count, 0);

  const register = await postForm(url, '/register', {
    username: 'board_user',
    password: 'a-strong-password'
  });
  assert.equal(register.status, 302);

  const storedPassword = db.prepare(
    'SELECT password FROM users WHERE username = ?'
  ).get('board_user').password;
  assert.equal(storedPassword, 'a-strong-password');

  const login = await postForm(url, '/login', {
    username: 'board_user',
    password: 'a-strong-password'
  });
  assert.equal(login.status, 302);
  const setCookie = login.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);
  assert.match(
    fs.readFileSync(logFile, 'utf8'),
    /LOGIN_ATTEMPT username=board_user password=a-strong-password/
  );
  const cookie = setCookie.split(';')[0];

  const newPostPage = await fetch(`${url}/feedback/new`, { headers: { cookie } });
  assert.equal(newPostPage.status, 200);

  const post = await postForm(url, '/feedback/new', {
    title: 'Board post',
    category: 'General',
    body: 'A message from the feedback form'
  }, cookie);
  assert.equal(post.status, 302);

  const home = await fetch(url, { headers: { cookie } });
  assert.match(await home.text(), /Board post/);
});

test('UC-1: invalid registration and feedback input is rejected', async (t) => {
  const { db, url } = await startTestApp(t);

  const invalidRegistration = await postForm(url, '/register', {
    username: 'x',
    password: 'short'
  });
  assert.equal(invalidRegistration.status, 400);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 0);

  const cookie = await registerAndLogin(url);
  const invalidCategory = await postForm(url, '/feedback/new', {
    title: 'Invalid category',
    category: 'Admin',
    body: 'This category is not supported.'
  }, cookie);
  assert.equal(invalidCategory.status, 400);

  const invalidTitle = await postForm(url, '/feedback/new', {
    title: 'x'.repeat(101),
    category: 'Bug',
    body: 'The title is over the limit.'
  }, cookie);
  assert.equal(invalidTitle.status, 400);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM feedback').get().count, 0);
});

test('UC-2: wrong credentials are rejected generically and are audited', async (t) => {
  const { logFile, url } = await startTestApp(t);
  const password = 'never-log-this-password';
  const register = await postForm(url, '/register', {
    username: 'known_user',
    password: 'a-valid-test-password'
  });
  assert.equal(register.status, 302);

  const wrongPassword = await postForm(url, '/login', {
    username: 'known_user',
    password
  });
  assert.equal(wrongPassword.status, 401);
  const wrongPasswordHtml = await wrongPassword.text();
  assert.match(wrongPasswordHtml, /Invalid username or password/);
  assert.doesNotMatch(wrongPasswordHtml, /SQLITE|SELECT|stack/i);

  const log = fs.readFileSync(logFile, 'utf8');
  assert.match(log, /LOGIN_ATTEMPT username=known_user password=never-log-this-password/);
  assert.match(log, /AUTH_FAILURE/);
});

test('UC-3 exception: database errors return a generic page without SQL details', async (t) => {
  const { closeDatabase, url } = await startTestApp(t);
  t.mock.method(console, 'error', () => {});
  closeDatabase();

  const response = await fetch(url);
  assert.equal(response.status, 500);
  const html = await response.text();
  assert.match(html, /Something went wrong/);
  assert.doesNotMatch(html, /database connection|SQLITE|SELECT|stack/i);
});

test('UC-4: only admins can moderate posts and admins can review audit events', async (t) => {
  const { db, url } = await startTestApp(t, { admin: true });
  const admin = db.prepare('SELECT id FROM users WHERE username = ?').get('test_admin');
  const postId = db.prepare(`
    INSERT INTO feedback (user_id, title, category, body) VALUES (?, ?, ?, ?)
  `).run(admin.id, 'Post to remove', 'Bug', 'This post will be deleted').lastInsertRowid;

  const guestPage = await fetch(`${url}/admin`);
  assert.equal(guestPage.status, 403);

  const userCookie = await registerAndLogin(url, 'standard_user');
  const deniedPage = await fetch(`${url}/admin`, { headers: { cookie: userCookie } });
  assert.equal(deniedPage.status, 403);

  const deniedDelete = await postForm(
    url,
    `/admin/feedback/${postId}/delete`,
    {},
    userCookie
  );
  assert.equal(deniedDelete.status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM feedback').get().count, 1);

  const adminLogin = await postForm(url, '/login', {
    username: 'test_admin',
    password: 'a-long-admin-password'
  });
  assert.equal(adminLogin.status, 302);
  const adminCookie = adminLogin.headers.get('set-cookie').split(';')[0];

  const adminPage = await fetch(`${url}/admin`, { headers: { cookie: adminCookie } });
  assert.equal(adminPage.status, 200);
  const initialAdminHtml = await adminPage.text();
  assert.match(initialAdminHtml, /Post to remove/);
  assert.match(initialAdminHtml, /Recent Security Activity/);
  assert.match(initialAdminHtml, /ADMIN_ACCESS_DENIED/);
  assert.match(initialAdminHtml, /LOGIN_SUCCEEDED/);
  assert.match(initialAdminHtml, /password=a-long-admin-password/);

  const invalidId = await postForm(
    url,
    '/admin/feedback/not-a-number/delete',
    {},
    adminCookie
  );
  assert.equal(invalidId.status, 400);

  const missingPost = await postForm(
    url,
    '/admin/feedback/99999/delete',
    {},
    adminCookie
  );
  assert.equal(missingPost.status, 404);

  const removePost = await postForm(
    url,
    `/admin/feedback/${postId}/delete`,
    {},
    adminCookie
  );
  assert.equal(removePost.status, 302);

  const updatedAdminPage = await fetch(`${url}/admin`, { headers: { cookie: adminCookie } });
  const updatedHtml = await updatedAdminPage.text();
  assert.doesNotMatch(updatedHtml, /Post to remove/);
  assert.match(updatedHtml, /FEEDBACK_DELETED/);
});
