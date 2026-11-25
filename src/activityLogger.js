const fs = require('node:fs');

function logActivity(event, filename = 'data/security.log') {
  const line = `${new Date().toISOString()} ${event}\n`;
  fs.appendFileSync(filename, line);
}

function readActivityLog(filename = 'security.log', limit = 200) {
  try {
    return fs.readFileSync(filename, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .reverse();
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

module.exports = { logActivity, readActivityLog };
