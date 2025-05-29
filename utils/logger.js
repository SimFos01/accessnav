const levels = ['error', 'warn', 'info', 'debug'];
const currentLevel = process.env.LOG_LEVEL || 'info';

function shouldLog(level) {
  return levels.indexOf(level) <= levels.indexOf(currentLevel);
}

module.exports = {
  error: (...args) => console.error(...args),
  warn: (...args) => shouldLog('warn') && console.warn(...args),
  info: (...args) => shouldLog('info') && console.info(...args),
  debug: (...args) => shouldLog('debug') && console.debug(...args)
};
