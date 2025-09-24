/**
 * 日志管理工具
 * 控制不同环境下的日志输出，仅在用户操作时记录重要信息
 */

// 日志级别
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

// 当前日志级别（生产环境默认为INFO，开发环境为INFO）
const CURRENT_LOG_LEVEL = process.env.NODE_ENV === 'production' ? LOG_LEVELS.INFO : LOG_LEVELS.INFO;

/**
 * 格式化日志时间
 * @returns {string} 格式化后的时间字符串
 */
function formatTime() {
  return new Date().toISOString().slice(0, 23).replace('T', ' ');
}

/**
 * 输出日志到控制台
 * @param {string} level 日志级别
 * @param {string} prefix 日志前缀
 * @param {...any} args 日志内容
 */
function logToConsole(level, prefix, ...args) {
  const timestamp = formatTime();
  const logPrefix = `[${timestamp}] [${level}] ${prefix}:`;
  
  switch (LOG_LEVELS[level]) {
    case LOG_LEVELS.ERROR:
      console.error(logPrefix, ...args);
      break;
    case LOG_LEVELS.WARN:
      console.warn(logPrefix, ...args);
      break;
    case LOG_LEVELS.INFO:
      console.info(logPrefix, ...args);
      break;
    case LOG_LEVELS.DEBUG:
      // DEBUG级别日志在INFO级别设置下不输出
      break;
    default:
      console.log(logPrefix, ...args);
  }
}

/**
 * 发送日志到主进程
 * @param {string} level 日志级别
 * @param {string} prefix 日志前缀
 * @param {...any} args 日志内容
 */
function logToMainProcess(level, prefix, ...args) {
  // 在Electron渲染进程中可用ipcRenderer发送日志到主进程
  try {
    const { ipcRenderer } = window.require('electron');
    if (ipcRenderer) {
      ipcRenderer.send('log-message', { level, prefix, args: args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : arg
      ) });
    }
  } catch (e) {
    // 如果无法获取ipcRenderer，则只在控制台输出
    logToConsole(level, prefix, ...args);
  }
}

class Logger {
  constructor(prefix) {
    this.prefix = prefix;
  }

  /**
   * 输出错误日志
   * @param {...any} args 日志内容
   */
  error(...args) {
    if (CURRENT_LOG_LEVEL >= LOG_LEVELS.ERROR) {
      logToConsole('ERROR', this.prefix, ...args);
      logToMainProcess('ERROR', this.prefix, ...args);
    }
  }

  /**
   * 输出警告日志
   * @param {...any} args 日志内容
   */
  warn(...args) {
    if (CURRENT_LOG_LEVEL >= LOG_LEVELS.WARN) {
      logToConsole('WARN', this.prefix, ...args);
      logToMainProcess('WARN', this.prefix, ...args);
    }
  }

  /**
   * 输出信息日志（仅用户操作相关）
   * @param {...any} args 日志内容
   */
  info(...args) {
    if (CURRENT_LOG_LEVEL >= LOG_LEVELS.INFO) {
      logToConsole('INFO', this.prefix, ...args);
      logToMainProcess('INFO', this.prefix, ...args);
    }
  }

  /**
   * 输出调试日志（默认不输出）
   * @param {...any} args 日志内容
   */
  debug(...args) {
    // 默认不输出DEBUG日志
  }
}

// 创建默认日志实例
export const logger = new Logger('App');

// 创建带前缀的日志实例工厂函数
export function createLogger(prefix) {
  return new Logger(prefix);
}

export default Logger;