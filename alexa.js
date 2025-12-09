const TelegramBot = require('node-telegram-bot-api');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const fs = require('fs');
require('dotenv').config();

// ════════════════════════════════════════════════════════════
// CONFIGURATION
// ════════════════════════════════════════════════════════════

const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

const ADMIN_USER_IDS = process.env.ADMIN_USER_IDS 
  ? process.env.ADMIN_USER_IDS.split(',').map(id => id.trim()) 
  : [];

const DEFAULT_USER_EMAIL = process.env.DEFAULT_USER_EMAIL || 'blackbarsee@gmail.com';

const ALLOWED_EMAIL_DOMAINS = (process.env.ALLOWED_EMAIL_DOMAINS
  ? process.env.ALLOWED_EMAIL_DOMAINS.split(',')
  : ['gmail.com', 'icornet.art']
).map(domain => domain.trim().toLowerCase()).filter(Boolean);

const DEFAULT_GMAIL_ACCOUNTS_RAW = process.env.DEFAULT_GMAIL_ACCOUNTS;
const DEFAULT_GMAIL_ACCOUNTS_FALLBACK = [
  'blackbarsee@gmail.com:zdjn fkdq wnum fmak',
  'blackbarsee@icornet.art:zdjn fkdq wnum fmak'
];

const gmailAccounts = [];

function parseAccountEntries(raw = '', label = 'GMAIL_ACCOUNTS') {
  return raw
    .split(/[\n;,]/)
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(entry => {
      const [user, passwordRaw] = entry.split(':');
      const password = (passwordRaw || '').replace(/\s+/g, '');

      if (user && password) {
        return { user, password };
      }

      console.error(`⚠️  Skipping invalid ${label} entry: ${entry}`);
      return null;
    })
    .filter(Boolean);
}

// Primary/secondary (legacy) support
const primaryGmailUser = process.env.GMAIL_USER;
const primaryGmailPassword = process.env.GMAIL_APP_PASSWORD
  ? process.env.GMAIL_APP_PASSWORD.replace(/\s+/g, '')
  : '';

const secondaryGmailUser = process.env.GMAIL_USER_2;
const secondaryGmailPassword = process.env.GMAIL_APP_PASSWORD_2
  ? process.env.GMAIL_APP_PASSWORD_2.replace(/\s+/g, '')
  : '';

// New: multi-account env (semicolon/comma/newline separated list of user:pass)
const multiAccountEnv = process.env.GMAIL_ACCOUNTS;

if (multiAccountEnv) {
  gmailAccounts.push(...parseAccountEntries(multiAccountEnv, 'GMAIL_ACCOUNTS'));
}

// Legacy fallback for backward compatibility
if (!multiAccountEnv) {
  if (primaryGmailUser && primaryGmailPassword) {
    gmailAccounts.push({ user: primaryGmailUser, password: primaryGmailPassword });
  }

  if (secondaryGmailUser && secondaryGmailPassword) {
    gmailAccounts.push({ user: secondaryGmailUser, password: secondaryGmailPassword });
  }
}

// Default bundle for two Gmail accounts if nothing is configured
if (gmailAccounts.length === 0) {
  const defaultAccounts = DEFAULT_GMAIL_ACCOUNTS_RAW
    ? parseAccountEntries(DEFAULT_GMAIL_ACCOUNTS_RAW, 'DEFAULT_GMAIL_ACCOUNTS')
    : parseAccountEntries(DEFAULT_GMAIL_ACCOUNTS_FALLBACK.join(';'), 'DEFAULT_GMAIL_ACCOUNTS');

  gmailAccounts.push(...defaultAccounts);

  const defaultSource = DEFAULT_GMAIL_ACCOUNTS_RAW ? 'env' : 'built-in fallback';
  console.log(`ℹ️  Loaded DEFAULT_GMAIL_ACCOUNTS from ${defaultSource} (update .env to override).`);
}

const NETFLIX_SENDER_ADDRESSES = (process.env.NETFLIX_SENDER_ADDRESSES
  ? process.env.NETFLIX_SENDER_ADDRESSES.split(',')
  : ['info@account.netflix.com']
).map(address => address.trim().toLowerCase()).filter(Boolean);

const BOT_NAME = process.env.BOT_NAME || 'Netflix Code Bot';
const BOT_VERSION = process.env.BOT_VERSION || '2.3.0';

const USERS_FILE = './authorized_users.json';
const STATS_FILE = './bot_stats.json';
const ACTIVITY_LOG_FILE = './activity_log.json';

// Auto-cleanup settings
const DATA_RETENTION_DAYS = 7; // Delete data older than 7 days
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // Check daily

// Rate limiting
const MAX_REQUESTS_PER_HOUR = 10;

// Validation
if (!TELEGRAM_TOKEN) {
  console.error('❌ MISSING: TELEGRAM_BOT_TOKEN in .env');
  process.exit(1);
}

if (gmailAccounts.length === 0) {
  console.error('❌ MISSING: Gmail credentials in .env');
  process.exit(1);
}

if (ADMIN_USER_IDS.length === 0) {
  console.error('⚠️  WARNING: No admin users configured');
}

// Startup Banner
console.log('\n' + '═'.repeat(60));
console.log(`🤖 ${BOT_NAME} v${BOT_VERSION}`);
console.log('═'.repeat(60));
console.log(`📧 Gmail Accounts: ${gmailAccounts.length}`);
gmailAccounts.forEach((account, index) => {
  const maskedEmail = account.user.replace(/(.{3}).*(@.*)/, '$1***$2');
  console.log(`   • [${index + 1}] ${maskedEmail}`);
});
console.log(`📝 Default user email: ${DEFAULT_USER_EMAIL || 'Not set'}`);
console.log(`🌐 Allowed email domains: ${ALLOWED_EMAIL_DOMAINS.join(', ') || 'Any'}`);
console.log(`🔑 App Passwords: ${gmailAccounts.length}`);
console.log(`📨 Netflix Senders: ${NETFLIX_SENDER_ADDRESSES.join(', ')}`);
console.log(`👤 Admin IDs: ${ADMIN_USER_IDS.length > 0 ? ADMIN_USER_IDS.join(', ') : 'Not set'}`);
console.log(`🗑️ Data Retention: ${DATA_RETENTION_DAYS} days`);
console.log(`📅 ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC`);
console.log('═'.repeat(60) + '\n');

// ════════════════════════════════════════════════════════════
// REQUEST QUEUE & RATE LIMITING
// ════════════════════════════════════════════════════════════

const userRequestQueue = {};
const userRateLimits = {};

function escapeMarkdown(text = '') {
  return text.toString().replace(/([_*\[\]()`])/g, '\\$1');
}

function sanitizeUserForMarkdown(user = {}) {
  return {
    fullName: escapeMarkdown(user.fullName || 'Unknown User'),
    username: escapeMarkdown(user.username || 'none'),
    email: escapeMarkdown(user.email || 'No email')
  };
}

function isUserBusy(userId) {
  return userRequestQueue[userId] === true;
}

function setUserBusy(userId) {
  userRequestQueue[userId] = true;
}

function setUserFree(userId) {
  delete userRequestQueue[userId];
}

function checkRateLimit(userId) {
  const now = Date.now();
  const hour = 60 * 60 * 1000;
  
  if (!userRateLimits[userId]) {
    userRateLimits[userId] = [];
  }
  
  // Remove old timestamps
  userRateLimits[userId] = userRateLimits[userId].filter(time => now - time < hour);
  
  if (userRateLimits[userId].length >= MAX_REQUESTS_PER_HOUR) {
    const oldestRequest = userRateLimits[userId][0];
    const timeUntilReset = Math.ceil((hour - (now - oldestRequest)) / 60000); // minutes
    return { allowed: false, waitMinutes: timeUntilReset };
  }
  
  userRateLimits[userId].push(now);
  return { allowed: true };
}

// ════════════════════════════════════════════════════════════
// MESSAGE CLEANUP SYSTEM - ADMIN KEEPS ALL, USERS GET CLEAN
// ════════════════════════════════════════════════════════════

const userMessages = {}; // Track user messages only

async function deleteMessageSafe(chatId, messageId, delay = 0) {
  if (delay === 0) {
    try {
      await bot.deleteMessage(chatId, messageId);
    } catch (e) {
      // Silently fail
    }
  } else {
    setTimeout(async () => {
      try {
        await bot.deleteMessage(chatId, messageId);
      } catch (e) {
        // Silently fail
      }
    }, delay);
  }
}

function trackUserMessage(userId, messageId) {
  if (!userMessages[userId]) {
    userMessages[userId] = [];
  }
  userMessages[userId].push(messageId);
}

// Clean previous message for NON-ADMIN users only
async function cleanPreviousMessages(userId, chatId) {
  // DON'T delete if user is admin!
  if (isAdmin(userId)) {
    return; // Admins keep all history
  }
  
  // Regular users: delete previous messages
  if (userMessages[userId] && userMessages[userId].length > 0) {
    for (const msgId of userMessages[userId]) {
      await deleteMessageSafe(chatId, msgId, 0);
    }
    userMessages[userId] = [];
  }
}

// ════════════════════════════════════════════════════════════
// DATA MANAGEMENT
// ════════════════════════════════════════════════════════════

let authorizedUsers = {};
let botStats = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  avgFetchTime: 0,
  startTime: new Date().toISOString()
};
let activityLog = [];
let awaitingEmailInput = {};

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = fs.readFileSync(USERS_FILE, 'utf8');
      authorizedUsers = JSON.parse(data);
      console.log(`✅ Loaded ${Object.keys(authorizedUsers).length} authorized users`);
    } else {
      authorizedUsers = {};
      saveUsers();
    }
  } catch (err) {
    console.error('❌ Error loading users:', err.message);
    authorizedUsers = {};
  }
}

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(authorizedUsers, null, 2));
  } catch (err) {
    console.error('❌ Error saving users:', err.message);
  }
}

function loadStats() {
  try {
    if (fs.existsSync(STATS_FILE)) {
      const data = fs.readFileSync(STATS_FILE, 'utf8');
      botStats = JSON.parse(data);
      console.log(`✅ Loaded bot statistics`);
    } else {
      saveStats();
    }
  } catch (err) {
    console.error('❌ Error loading stats:', err.message);
  }
}

function saveStats() {
  try {
    fs.writeFileSync(STATS_FILE, JSON.stringify(botStats, null, 2));
  } catch (err) {
    console.error('❌ Error saving stats:', err.message);
  }
}

function loadActivityLog() {
  try {
    if (fs.existsSync(ACTIVITY_LOG_FILE)) {
      const data = fs.readFileSync(ACTIVITY_LOG_FILE, 'utf8');
      activityLog = JSON.parse(data);
      console.log(`✅ Loaded ${activityLog.length} activity logs`);
      
      if (activityLog.length > 100) {
        activityLog = activityLog.slice(-100);
        saveActivityLog();
      }
    } else {
      activityLog = [];
      saveActivityLog();
    }
  } catch (err) {
    console.error('❌ Error loading activity log:', err.message);
    activityLog = [];
  }
}

function saveActivityLog() {
  try {
    fs.writeFileSync(ACTIVITY_LOG_FILE, JSON.stringify(activityLog, null, 2));
  } catch (err) {
    console.error('❌ Error saving activity log:', err.message);
  }
}

// ════════════════════════════════════════════════════════════
// AUTO-CLEANUP OLD DATA (7 DAYS)
// ════════════════════════════════════════════════════════════

async function cleanupOldData() {
  const now = Date.now();
  const retentionMs = DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  
  console.log('\n🗑️ Running auto-cleanup...');
  
  // Prepare weekly report
  let reportText = `📊 *WEEKLY DATA CLEANUP REPORT*\n\n`;
  reportText += `📅 ${new Date().toISOString().replace('T', ' ').split('.')[0]}\n\n`;
  
  // Clean old activity logs
  const oldLogCount = activityLog.length;
  activityLog = activityLog.filter(log => {
    const logAge = now - new Date(log.timestamp).getTime();
    return logAge < retentionMs;
  });
  const deletedLogs = oldLogCount - activityLog.length;
  
  reportText += `📋 *Activity Logs:*\n`;
  reportText += `   • Deleted: ${deletedLogs} old entries\n`;
  reportText += `   • Kept: ${activityLog.length} entries\n\n`;
  
  // Clean old user request history
  let totalRequestsDeleted = 0;
  let usersAffected = 0;
  
  Object.keys(authorizedUsers).forEach(userId => {
    const user = authorizedUsers[userId];
    
    if (user.requestHistory && user.requestHistory.length > 0) {
      const oldHistoryCount = user.requestHistory.length;
      
      user.requestHistory = user.requestHistory.filter(req => {
        const reqAge = now - new Date(req.timestamp).getTime();
        return reqAge < retentionMs;
      });
      
      const deleted = oldHistoryCount - user.requestHistory.length;
      
      if (deleted > 0) {
        totalRequestsDeleted += deleted;
        usersAffected++;
      }
    }
  });
  
  reportText += `👥 *User Request History:*\n`;
  reportText += `   • Users affected: ${usersAffected}\n`;
  reportText += `   • Requests deleted: ${totalRequestsDeleted}\n\n`;
  
  // Save cleaned data
  saveActivityLog();
  saveUsers();
  
  reportText += `✅ Cleanup complete!\n`;
  reportText += `💾 Data older than ${DATA_RETENTION_DAYS} days removed`;
  
  console.log(`✅ Cleanup complete: ${deletedLogs} logs + ${totalRequestsDeleted} requests deleted`);
  
  // Send report to all admins
  if (ADMIN_USER_IDS.length > 0 && bot) {
    for (const adminId of ADMIN_USER_IDS) {
      try {
        await bot.sendMessage(adminId, reportText, { parse_mode: 'Markdown' });
      } catch (e) {
        console.error(`❌ Failed to send cleanup report to admin ${adminId}:`, e.message);
      }
    }
  }
}

// ════════════════════════════════════════════════════════════
// EMAIL VALIDATION
// ════════════════════════════════════════════════════════════

function isValidEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  if (!regex.test(email)) {
    return { valid: false, reason: 'Invalid email format' };
  }
  
  // Block obvious temporary email services
  const blockedDomains = [
    'tempmail.com', 'guerrillamail.com', '10minutemail.com', 
    'throwaway.email', 'mailinator.com', 'trash-mail.com'
  ];
  
  const domain = email.toLowerCase().split('@')[1];

  if (blockedDomains.includes(domain)) {
    return { valid: false, reason: 'Temporary email services not allowed' };
  }

  if (ALLOWED_EMAIL_DOMAINS.length > 0 && !ALLOWED_EMAIL_DOMAINS.includes(domain)) {
    return {
      valid: false,
      reason: `Email domain must be one of: ${ALLOWED_EMAIL_DOMAINS.join(', ')}`
    };
  }

  return { valid: true, reason: null };
}

function isDefaultEmailValid() {
  return DEFAULT_USER_EMAIL && isValidEmail(DEFAULT_USER_EMAIL).valid;
}

// ════════════════════════════════════════════════════════════
// USER MANAGEMENT
// ════════════════════════════════════════════════════════════

function addUser(userId, username, firstName, lastName) {
  const fullName = `${firstName || ''} ${lastName || ''}`.trim() || 'Unknown';
  const defaultEmailValid = isDefaultEmailValid();

  authorizedUsers[userId] = {
    userId: userId,
    username: username || null,
    fullName: fullName,
    email: defaultEmailValid ? DEFAULT_USER_EMAIL : null,
    addedDate: new Date().toISOString(),
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    lastRequest: null,
    lastCode: null,
    lastCodeType: null,
    requestHistory: []
  };
  saveUsers();
  console.log(`➕ User added: ${fullName} (@${username || 'none'}) - ID: ${userId}`);
}

function isAuthorized(userId) {
  return authorizedUsers.hasOwnProperty(userId.toString());
}

function isAdmin(userId) {
  return ADMIN_USER_IDS.includes(userId.toString());
}

function removeUser(userId) {
  if (authorizedUsers[userId]) {
    const user = authorizedUsers[userId];
    delete authorizedUsers[userId];
    saveUsers();
    console.log(`➖ User removed: ${user.fullName} - ID: ${userId}`);
    return true;
  }
  return false;
}

function trackUsage(userId, success, timeTaken, code = null, codeType = null, emailFrom = null, folder = null) {
  const user = authorizedUsers[userId];
  if (user) {
    user.totalRequests++;
    if (success) {
      user.successfulRequests++;
      user.lastCode = code;
      user.lastCodeType = codeType;
    } else {
      user.failedRequests++;
    }
    user.lastRequest = new Date().toISOString();
    
    user.requestHistory.unshift({
      timestamp: new Date().toISOString(),
      success: success,
      codeType: codeType,
      code: code,
      emailFrom: emailFrom,
      folder: folder,
      fetchTime: timeTaken
    });
    
    if (user.requestHistory.length > 50) {
      user.requestHistory = user.requestHistory.slice(0, 50);
    }
    
    saveUsers();
  }
  
  botStats.totalRequests++;
  if (success) {
    botStats.successfulRequests++;
  } else {
    botStats.failedRequests++;
  }
  
  const currentAvg = botStats.avgFetchTime;
  const currentTotal = botStats.totalRequests;
  botStats.avgFetchTime = ((currentAvg * (currentTotal - 1)) + timeTaken) / currentTotal;
  
  saveStats();
}

// ════════════════════════════════════════════════════════════
// ACTIVITY LOGGING
// ════════════════════════════════════════════════════════════

async function logActivity(userId, action, details = {}) {
  const user = authorizedUsers[userId];
  const timestamp = new Date().toISOString();
  
  const logEntry = {
    timestamp: timestamp,
    userId: userId,
    username: user?.username || 'unknown',
    fullName: user?.fullName || 'Unknown User',
    email: user?.email || 'No email',
    action: action,
    ...details
  };
  
  activityLog.unshift(logEntry);
  
  if (activityLog.length > 100) {
    activityLog = activityLog.slice(0, 100);
  }
  
  saveActivityLog();
  
  // Send real-time notification to all admins
  if (ADMIN_USER_IDS.length > 0 && !ADMIN_USER_IDS.includes(userId.toString()) && bot) {
    try {
      let notificationText = '';
      const safeUser = sanitizeUserForMarkdown(user || {});
      const safeDetails = {
        email: escapeMarkdown(details.email || ''),
        signInCode: escapeMarkdown(details.signInCode || ''),
        householdLink: escapeMarkdown(details.householdLink || ''),
        resetLink: escapeMarkdown(details.resetLink || ''),
        folder: escapeMarkdown(details.folder || '')
      };
      const safeTimestamp = escapeMarkdown(timestamp.replace('T', ' ').split('.')[0]);

      if (action === 'fetch_signin_code') {
        notificationText =
          `✅ *SIGN-IN CODE FETCHED*\n\n` +
          `👤 ${safeUser.fullName} (@${safeUser.username})\n` +
          `📧 \`${safeUser.email}\`\n\n` +
          `🔐 CODE: \`${safeDetails.signInCode}\`\n` +
          `📂 ${safeDetails.folder}\n` +
          `⏱️ ${details.fetchTime}s\n` +
          `📅 ${safeTimestamp}`;

      } else if (action === 'fetch_household_link') {
        notificationText =
          `✅ *HOUSEHOLD LINK FETCHED*\n\n` +
          `👤 ${safeUser.fullName} (@${safeUser.username})\n` +
          `📧 \`${safeUser.email}\`\n\n` +
          `🔗 ${safeDetails.householdLink}\n` +
          `📂 ${safeDetails.folder}\n` +
          `⏱️ ${details.fetchTime}s\n` +
          `📅 ${safeTimestamp}`;

      } else if (action === 'fetch_password_reset') {
        notificationText =
          `🔑 *PASSWORD RESET FETCHED*\n\n` +
          `👤 ${safeUser.fullName} (@${safeUser.username})\n` +
          `📧 \`${safeUser.email}\`\n\n` +
          `🔗 ${safeDetails.resetLink}\n` +
          `📂 ${safeDetails.folder}\n` +
          `⏱️ ${details.fetchTime}s\n` +
          `📅 ${safeTimestamp}`;

      } else if (action === 'email_configured') {
        notificationText =
          `📧 *EMAIL CONFIGURED*\n\n` +
          `👤 ${safeUser.fullName}\n` +
          `📧 \`${safeDetails.email}\`\n` +
          `📅 ${safeTimestamp}`;

      } else if (action === 'unauthorized_access') {
        notificationText =
          `🚫 *UNAUTHORIZED ACCESS*\n\n` +
          `👤 ${escapeMarkdown(details.fullName || 'Unknown User')}\n` +
          `🆔 @${escapeMarkdown(details.username || 'none')}\n` +
          `🔢 \`${userId}\`\n\n` +
          `💡 /add ${userId}`;
      }
      
      if (notificationText) {
        for (const adminId of ADMIN_USER_IDS) {
          if (adminId !== userId.toString()) {
            try {
              await bot.sendMessage(adminId, notificationText, { parse_mode: 'Markdown' });
            } catch (e) {
              console.error(`❌ Failed to notify admin ${adminId}:`, e.message);
            }
          }
        }
      }

    } catch (e) {
      console.error('❌ Error in admin notification:', e.message);
    }
  }

  console.log(`📝 ${action} by ${user?.fullName || userId} ${user?.email ? '(' + user.email + ')' : ''}`);
}

// ════════════════════════════════════════════════════════════
// ACCESS REQUEST NOTIFICATIONS
// ════════════════════════════════════════════════════════════

async function notifyAdminsOfAccessRequest(userId, fullName, username) {
  if (!bot || ADMIN_USER_IDS.length === 0) {
    return;
  }

  const safeFullName = escapeMarkdown(fullName || 'Unknown User');
  const safeUsername = escapeMarkdown(username || 'none');
  const safeUserId = escapeMarkdown(userId);

  const requestText =
    `🚫 *ACCESS REQUEST*\n\n` +
    `👤 ${safeFullName}\n` +
    `🆔 \`${safeUserId}\`\n` +
    `🔗 @${safeUsername}\n\n` +
    `Approve to allow /start access.`;

  for (const adminId of ADMIN_USER_IDS) {
    try {
      await bot.sendMessage(adminId, requestText, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '✅ Approve', callback_data: `approve_user:${userId}` }]
          ]
        }
      });
    } catch (err) {
      console.error(`❌ Failed to notify admin ${adminId} about access request:`, err.message);
    }
  }
}

// ════════════════════════════════════════════════════════════
// TYPE-SPECIFIC NETFLIX EMAIL DETECTION
// ════════════════════════════════════════════════════════════

function detectAndExtract(text = '', html = '', subject = '', searchType = 'signin') {
  const combined = (subject + '\n' + text + '\n' + html)
    .replace(/\u00A0/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  
  // TYPE 1: Sign-In Code ONLY
  if (searchType === 'signin') {
    if (combined.match(/sign[\s-]in code/i) || combined.match(/enter this code/i)) {
      const codePatterns = [
        /enter this code to sign in[\s\S]{0,50}?(\d{4})/i,
        /enter this code[\s\S]{0,50}?(\d{4})/i,
        /(\d{4})/
      ];
      
      for (const pattern of codePatterns) {
        const match = combined.match(pattern);
        if (match && match[1] && /^\d{4}$/.test(match[1])) {
          return {
            type: 'signin',
            content: match[1]
          };
        }
      }
    }
    return null;
  }
  
  // TYPE 2: Household Link ONLY
  if (searchType === 'household') {
    if (combined.match(/temporary access code/i) || combined.match(/travel/i) || combined.match(/household/i) || combined.match(/get code/i)) {
      const linkPattern = /https?:\/\/(?:www\.)?netflix\.com\/[^\s<>"']+/gi;
      const match = combined.match(linkPattern);
      if (match && match[0]) {
        return {
          type: 'household',
          content: match[0].replace(/<[^>]+>/g, '').trim()
        };
      }
    }
    return null;
  }
  
  // TYPE 3: Password Reset ONLY
  if (searchType === 'reset') {
    if (combined.match(/reset.*password/i) || combined.match(/complete your password reset/i)) {
      const linkPattern = /https?:\/\/(?:www\.)?netflix\.com\/[^\s<>"']+/gi;
      const match = combined.match(linkPattern);
      if (match && match[0]) {
        return {
          type: 'reset',
          content: match[0].replace(/<[^>]+>/g, '').trim()
        };
      }
    }
    return null;
  }
  
  return null;
}

// ════════════════════════════════════════════════════════════
// GMAIL IMAP FETCH - LAST 30 MIN ONLY (READ/UNREAD, INBOX/SPAM)
// ════════════════════════════════════════════════════════════


function fetchNetflixEmail(userEmail, searchType = 'signin') {
  const startTime = Date.now();
  const attemptErrors = [];
  let anyAccountConnected = false;

  function maskEmailForLog(email = '') {
    return email.replace(/(.{3}).*(@.*)/, '$1***$2');
  }

  function senderMatches(addresses = []) {
    return addresses.some(address => {
      if (!address) return false;
      const normalized = address.toLowerCase();
      return NETFLIX_SENDER_ADDRESSES.some(sender => {
        if (sender.includes('@')) {
          return normalized === sender;
        }
        return normalized.endsWith(`@${sender}`);
      });
    });
  }

  function searchWithAccount(account) {
    return new Promise((resolve) => {
      const imap = new Imap({
        user: account.user,
        password: account.password,
        host: 'imap.gmail.com',
        port: 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false },
        connTimeout: 5000,
        authTimeout: 5000
      });

      let result = null;
      let finished = false;

      function finish() {
        if (finished) return;
        finished = true;

        try {
          imap.end();
        } catch (e) {}

        if (result) {
          result.timeTaken = Math.round((Date.now() - startTime) / 1000);
          result.account = account.user;
        }

        resolve(result);
      }

      imap.once('ready', () => {
        anyAccountConnected = true;
        // Search INBOX first
        searchFolder('INBOX', (inboxResult) => {
          if (inboxResult) {
            result = inboxResult;
            finish();
          } else {
            // If not found in INBOX, search SPAM
            searchFolder('[Gmail]/Spam', (spamResult) => {
              if (spamResult) {
                result = spamResult;
              }
              finish();
            });
          }
        });

        function searchFolder(folderName, callback) {
          imap.openBox(folderName, false, (err) => {
            if (err) {
              console.error(`❌ Error opening ${folderName}:`, err.message);
              return callback(null);
            }

            // Search last 30 minutes ONLY (read or unread)
            const sinceDate = new Date();
            sinceDate.setMinutes(sinceDate.getMinutes() - 30);

            const searchCriteria = [
              ['SINCE', sinceDate],
              ['TO', userEmail]
            ];

            imap.search(searchCriteria, (err, results) => {
              if (err) {
                console.error(`❌ IMAP search error in ${folderName}:`, err.message);
                return callback(null);
              }

              if (!results || results.length === 0) {
                console.log(`📭 No emails for ${userEmail} in ${folderName}`);
                return callback(null);
              }

              console.log(`📬 Found ${results.length} email(s) for ${userEmail} in ${folderName} (${account.user})`);

              // Process ALL emails from last 30 min, find the most recent matching one
              processEmails(results, folderName, callback);
            });
          });
        }

        function processEmails(results, folder, callback) {
          let foundResult = null;
          let processedCount = 0;

          // Fetch all emails
          const f = imap.fetch(results, { bodies: '', struct: true });

          f.on('message', (msg) => {
            msg.on('body', (stream) => {
              simpleParser(stream, (err, parsed) => {
                if (err) {
                  console.error('❌ Error parsing email:', err.message);
                  processedCount++;
                  return;
                }

                const fromAddresses = (parsed.from?.value || [])
                  .map(entry => (entry.address || '').toLowerCase())
                  .filter(Boolean);

                if (!senderMatches(fromAddresses)) {
                  processedCount++;
                  return;
                }

                const emailDate = parsed.date || new Date();

                // Check if email is within last 30 minutes
                const emailAge = Date.now() - emailDate.getTime();
                const thirtyMinutesMs = 30 * 60 * 1000;

                if (emailAge > thirtyMinutesMs) {
                  console.log(`⏰ Email too old (${Math.floor(emailAge / 60000)}m ago), skipping`);
                  processedCount++;
                  return;
                }

                const extracted = detectAndExtract(
                  parsed.text || '',
                  parsed.html || '',
                  parsed.subject || '',
                  searchType
                );

                if (extracted) {
                  // Found matching email
                  if (!foundResult || emailDate > foundResult.date) {
                    // Keep the most recent one
                    foundResult = {
                      type: extracted.type,
                      content: extracted.content,
                      from: parsed.from?.text || 'Unknown',
                      to: parsed.to?.text || userEmail,
                      subject: parsed.subject || '',
                      date: emailDate,
                      folder: folder,
                      account: account.user
                    };

                    const elapsed = Math.round((Date.now() - startTime) / 1000);
                    console.log(`✅ Found ${extracted.type} for ${userEmail} in ${folder} (${elapsed}s, ${Math.floor(emailAge / 60000)}m old)`);
                  }
                }

                processedCount++;
              });
            });
          });

          f.once('error', (err) => {
            console.error('❌ Fetch error:', err.message);
            callback(null);
          });

          f.once('end', () => {
            // Wait a bit for all emails to be processed
            setTimeout(() => {
              callback(foundResult);
            }, 2000);
          });
        }
      });

      imap.once('error', (err) => {
        console.error('❌ IMAP connection error:', err.message);
        attemptErrors.push({ account: account.user, message: err.message });
        finish();
      });

      imap.connect();

      setTimeout(() => {
        if (!finished) {
          console.log('⏱️ Timeout (10s)');
          finish();
        }
      }, 10000);
    });
  }

  const accountsToTry = gmailAccounts.length > 0 ? gmailAccounts : [];

  const attemptsPromise = accountsToTry.reduce((promise, account) => {
    return promise.then((res) => {
      if (res) return res;
      return searchWithAccount(account);
    });
  }, Promise.resolve(null));

  return attemptsPromise.then((result) => {
    if (result) return result;

    if (!anyAccountConnected && attemptErrors.length === accountsToTry.length) {
      const errorSummary = attemptErrors
        .map(({ account, message }) => `${maskEmailForLog(account)} (${message})`)
        .join('; ');

      throw new Error(`All IMAP accounts failed: ${errorSummary}`);
    }

    return null;
  });
}

// ════════════════════════════════════════════════════════════
// BETTER ERROR MESSAGES
// ════════════════════════════════════════════════════════════

function getErrorMessage(error) {
  const msg = error.message || '';
  
  if (msg.includes('EAUTH') || msg.includes('Invalid credentials')) {
    return 'Gmail authentication failed. Contact admin to check credentials.';
  }
  
  if (msg.includes('ETIMEDOUT') || msg.includes('timeout')) {
    return 'Connection timeout. Gmail is slow or unreachable. Try again.';
  }
  
  if (msg.includes('ECONNREFUSED')) {
    return 'Cannot connect to Gmail. Check internet connection.';
  }
  
  if (msg.includes('ENOTFOUND')) {
    return 'Gmail server not found. DNS issue.';
  }
  
  if (msg.includes('SELF_SIGNED_CERT')) {
    return 'SSL certificate error. Contact admin.';
  }
  
  return `Error: ${msg.substring(0, 100)}`;
}

// ════════════════════════════════════════════════════════════
// BOT INITIALIZATION
// ════════════════════════════════════════════════════════════

let bot;
let pollingRestarts = 0;
const MAX_RESTART_ATTEMPTS = 3;
const RESTART_DELAYS = [5000, 15000, 30000];

function initBot() {
  if (bot) {
    console.log('⚠️ Bot already initialized');
    return;
  }

  bot = new TelegramBot(TELEGRAM_TOKEN, { 
    polling: {
      interval: 300,
      autoStart: true,
      params: {
        timeout: 10
      }
    }
  });

  bot.on('polling_error', async (error) => {
    console.error('❌ Polling:', error.code || 'UNKNOWN', '-', error.message);

    if (error.code === 'ETELEGRAM' && error.message && error.message.includes('409 Conflict')) {
      console.error('🚨 409 CONFLICT: Another instance running!');
      
      try {
        await bot.stopPolling();
      } catch (e) {}
      
      process.exit(1);
    }

    if (error.code === 'EFATAL') {
      if (pollingRestarts >= MAX_RESTART_ATTEMPTS) {
        console.error(`🚫 Max restart attempts reached`);
        
        try {
          await bot.stopPolling();
        } catch (e) {}
        
        process.exit(1);
      }

      const delay = RESTART_DELAYS[pollingRestarts] || 30000;
      pollingRestarts++;
      
      console.log(`🔄 Restart ${pollingRestarts}/${MAX_RESTART_ATTEMPTS} in ${delay / 1000}s...`);

      setTimeout(async () => {
        try {
          await bot.stopPolling();
          await new Promise(resolve => setTimeout(resolve, 2000));
          await bot.startPolling();
          
          console.log('✅ Polling restarted!');
          pollingRestarts = 0;
          
        } catch (restartError) {
          console.error('❌ Restart failed:', restartError.message);
          
          if (pollingRestarts >= MAX_RESTART_ATTEMPTS) {
            process.exit(1);
          }
        }
      }, delay);
    }
  });

  setupHandlers();
  
  // Start auto-cleanup scheduler (runs daily)
  setInterval(cleanupOldData, CLEANUP_INTERVAL);
  console.log(`✅ Auto-cleanup scheduler started (every ${CLEANUP_INTERVAL / 3600000}h)`);
}

// ════════════════════════════════════════════════════════════
// KEYBOARD LAYOUTS
// ════════════════════════════════════════════════════════════

function getMainKeyboard(hasEmail) {
  if (!hasEmail) {
    return {
      reply_markup: {
        inline_keyboard: [
          [{ text: '📧 Setup Email', callback_data: 'setup_email' }],
          [{ text: '❓ Help', callback_data: 'help' }]
        ]
      }
    };
  }
  
  return {
    reply_markup: {
      inline_keyboard: [
        [{ text: '🏠 Household', callback_data: 'fetch_household' }],
        [{ text: '🔑 Reset', callback_data: 'fetch_reset' }],
        [{ text: '📱 Sign-in', callback_data: 'fetch_signin' }],
        [{ text: '📧 Change Email', callback_data: 'setup_email' }, { text: '📊 Stats', callback_data: 'my_stats' }],
        [{ text: '❓ Help', callback_data: 'help' }]
      ]
    }
  };
}

function getAdminKeyboard() {
  return {
    reply_markup: {
      inline_keyboard: [
        [{ text: '🏠 Household', callback_data: 'fetch_household' }],
        [{ text: '🔑 Reset', callback_data: 'fetch_reset' }],
        [{ text: '📱 Sign-in', callback_data: 'fetch_signin' }],
        [{ text: '📧 Change Email', callback_data: 'setup_email' }, { text: '📊 My Stats', callback_data: 'my_stats' }],
        [{ text: '📊 Bot Stats', callback_data: 'admin_stats' }, { text: '👥 Users', callback_data: 'admin_users' }],
        [{ text: '📋 Activity', callback_data: 'admin_activity' }, { text: '❓ Help', callback_data: 'help' }]
      ]
    }
  };
}

// ════════════════════════════════════════════════════════════
// BOT HANDLERS
// ════════════════════════════════════════════════════════════

function setupHandlers() {
  
  bot.onText(/\/start/, async (msg) => {
    const userId = msg.from.id.toString();
    const username = msg.from.username;
    const firstName = msg.from.first_name;
    const lastName = msg.from.last_name;
    const fullName = `${firstName || ''} ${lastName || ''}`.trim();
    const safeFirstName = escapeMarkdown(firstName || '');
    const safeFullName = escapeMarkdown(fullName || 'Unknown');
    const safeUsername = escapeMarkdown(username || 'none');

    if (isAdmin(userId) && !isAuthorized(userId)) {
      addUser(userId, username, firstName, lastName);
    }
    
    if (!isAuthorized(userId)) {
      await logActivity(userId, 'unauthorized_access', {
        fullName: fullName,
        username: username
      });

      await notifyAdminsOfAccessRequest(userId, fullName, username);

      return bot.sendMessage(msg.chat.id,
        `🚫 *ACCESS DENIED*\n\n` +
        `You are not authorized.\n\n` +
        `👤 ${safeFullName}\n` +
        `🆔 @${safeUsername}\n` +
        `🔢 \`${userId}\`\n\n`,
        {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: 'ℹ️ Awaiting approval', callback_data: 'help' }]
            ]
          }
        }
      );
    }
    
    if (authorizedUsers[userId]) {
      authorizedUsers[userId].username = username || null;
      authorizedUsers[userId].fullName = fullName;
      if (!authorizedUsers[userId].email && isDefaultEmailValid()) {
        authorizedUsers[userId].email = DEFAULT_USER_EMAIL;
      }
      saveUsers();
    }
    
    await logActivity(userId, 'started_bot');
    
    const user = authorizedUsers[userId];
    const hasEmail = !!user.email;
    const isAdminUser = isAdmin(userId);
    const keyboard = isAdminUser ? getAdminKeyboard() : getMainKeyboard(hasEmail);
    
    const welcomeText = hasEmail ?
      `👋 Welcome, *${safeFirstName}*!\n\n` +
      `✅ Email: \`${escapeMarkdown(user.email)}\`\n\n` +
      `Choose: 👇`
      :
      `👋 Welcome, *${safeFirstName}*!\n\n` +
      `🤖 *${BOT_NAME}*\n\n` +
      `*Setup:*\n` +
      `📧 Add email\n` +
      `🎯 Get codes instantly\n\n` +
      `Click "Setup Email" 👇`;
    
    await bot.sendMessage(msg.chat.id, welcomeText, {
      parse_mode: 'Markdown',
      ...keyboard
    });
  });

  bot.onText(/\/add (.+)/, async (msg, match) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    const targetUserId = match[1].trim();
    
    if (isAuthorized(targetUserId)) {
      return bot.sendMessage(msg.chat.id, `⚠️ Already authorized: ${targetUserId}`);
    }
    
    addUser(targetUserId, 'pending', 'Pending', '');
    
    await bot.sendMessage(msg.chat.id,
      `✅ *USER AUTHORIZED*\n\n` +
      `🔢 \`${targetUserId}\`\n` +
      `📅 ${new Date().toISOString().replace('T', ' ').split('.')[0]}\n\n` +
      `User can now /start`,
      { parse_mode: 'Markdown' }
    );
  });

  bot.onText(/\/remove (.+)/, async (msg, match) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    const targetUserId = match[1].trim();
    
    if (removeUser(targetUserId)) {
      await bot.sendMessage(msg.chat.id, `✅ *REMOVED*: \`${targetUserId}\``, { parse_mode: 'Markdown' });
    } else {
      await bot.sendMessage(msg.chat.id, `❌ Not found: \`${targetUserId}\``, { parse_mode: 'Markdown' });
    }
  });
  
  bot.onText(/\/cleanup/, async (msg) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    await bot.sendMessage(msg.chat.id, `🗑️ Running cleanup...`);
    
    await cleanupOldData();
    
    await bot.sendMessage(msg.chat.id, `✅ Cleanup complete!`);
  });

  bot.onText(/\/storage/, async (msg) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    try {
      const usersSize = fs.statSync(USERS_FILE).size;
      const statsSize = fs.statSync(STATS_FILE).size;
      const activitySize = fs.statSync(ACTIVITY_LOG_FILE).size;
      const totalSize = usersSize + statsSize + activitySize;
      
      const toKB = (bytes) => (bytes / 1024).toFixed(2);
      
      const now = Date.now();
      const retentionMs = DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000;
      
      let oldDataCount = 0;
      activityLog.forEach(log => {
        const age = now - new Date(log.timestamp).getTime();
        if (age > retentionMs) oldDataCount++;
      });
      
      await bot.sendMessage(msg.chat.id,
        `💾 *STORAGE INFO*\n\n` +
        `*Files:*\n` +
        `📄 Users: ${toKB(usersSize)} KB\n` +
        `📄 Stats: ${toKB(statsSize)} KB\n` +
        `📄 Activity: ${toKB(activitySize)} KB\n` +
        `📦 Total: ${toKB(totalSize)} KB\n\n` +
        `*Data:*\n` +
        `👥 ${Object.keys(authorizedUsers).length} users\n` +
        `📋 ${activityLog.length} logs\n` +
        `🗑️ ${oldDataCount} old (>7d)\n\n` +
        `*Retention:*\n` +
        `⏰ ${DATA_RETENTION_DAYS} days\n` +
        `🔄 Auto-cleanup: Daily`,
        { parse_mode: 'Markdown' }
      );
    } catch (e) {
      await bot.sendMessage(msg.chat.id, `❌ Error: ${e.message}`);
    }
  });

  bot.onText(/\/clearall/, async (msg) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    await bot.sendMessage(msg.chat.id,
      `⚠️ *CLEAR ALL DATA*\n\n` +
      `This will delete:\n` +
      `• All activity logs\n` +
      `• All user request history\n` +
      `• Bot stats\n\n` +
      `Users and emails will be kept.\n\n` +
      `Type: /confirmclear`,
      { parse_mode: 'Markdown' }
    );
  });

  bot.onText(/\/confirmclear/, async (msg) => {
    const adminId = msg.from.id.toString();
    
    if (!isAdmin(adminId)) {
      return bot.sendMessage(msg.chat.id, '🔒 Admin only!');
    }
    
    // Clear activity log
    activityLog = [];
    saveActivityLog();
    
    // Clear user request history
    Object.keys(authorizedUsers).forEach(userId => {
      authorizedUsers[userId].requestHistory = [];
    });
    saveUsers();
    
    // Reset stats (keep start time)
    const startTime = botStats.startTime;
    botStats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      avgFetchTime: 0,
      startTime: startTime
    };
    saveStats();
    
    await bot.sendMessage(msg.chat.id,
      `✅ *ALL DATA CLEARED*\n\n` +
      `📋 Activity log: empty\n` +
      `📊 User history: cleared\n` +
      `📈 Stats: reset\n\n` +
      `👥 Users preserved: ${Object.keys(authorizedUsers).length}`,
      { parse_mode: 'Markdown' }
    );
    
    console.log('🗑️ Admin cleared all data');
  });

  bot.on('callback_query', async (query) => {
    const userId = query.from.id.toString();
    const chatId = query.message.chat.id;
    const data = query.data;
    
    await bot.answerCallbackQuery(query.id).catch(() => {});

    if (!isAuthorized(userId)) {
      if (data === 'help') {
        return bot.sendMessage(chatId,
          `⏳ *WAITING FOR APPROVAL*\n\n` +
          `Your access request has been sent to the admins.\n` +
          `Share your ID if needed: \`${escapeMarkdown(userId)}\``,
          { parse_mode: 'Markdown' }
        );
      }

      return bot.sendMessage(chatId, `🚫 Unauthorized!`);
    }
    
    const user = authorizedUsers[userId];
    const isAdminUser = isAdmin(userId);

    if (data.startsWith('approve_user:')) {
      if (!isAdminUser) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }

      const [, targetUserId] = data.split(':');

      if (!targetUserId) {
        return bot.sendMessage(chatId, '❌ Invalid user id');
      }

      if (isAuthorized(targetUserId)) {
        return bot.sendMessage(chatId, `⚠️ Already authorized: \`${escapeMarkdown(targetUserId)}\``, { parse_mode: 'Markdown' });
      }

      addUser(targetUserId, 'pending', 'Pending', '');
      await logActivity(targetUserId, 'admin_approved_user', { approvedBy: userId });

      return bot.sendMessage(chatId,
        `✅ *USER APPROVED*\n\n` +
        `🔢 \`${escapeMarkdown(targetUserId)}\`\n` +
        `📅 ${new Date().toISOString().replace('T', ' ').split('.')[0]}\n\n` +
        `User can now /start`,
        { parse_mode: 'Markdown' }
      );
    }

    if (data === 'setup_email') {
      await cleanPreviousMessages(userId, chatId);

      awaitingEmailInput[userId] = true;

      const defaultEmailValid = isDefaultEmailValid();
      const inline_keyboard = [];

      if (defaultEmailValid) {
        inline_keyboard.push([{ text: `Use ${DEFAULT_USER_EMAIL}`, callback_data: 'use_default_email' }]);
      }

      inline_keyboard.push([{ text: '❌ Cancel', callback_data: 'cancel_email' }]);

      const emailMsg = await bot.sendMessage(chatId,
        `📧 *EMAIL SETUP*\n\n` +
        `Send your email:\n\n` +
        `Example: \`user@domain.com\``,
        {
          parse_mode: 'Markdown',
          reply_markup: { inline_keyboard }
        }
      );
      
      if (!isAdminUser) {
        trackUserMessage(userId, emailMsg.message_id);
      }
      
      return;
    }
    
    if (data === 'cancel_email') {
      delete awaitingEmailInput[userId];
      await cleanPreviousMessages(userId, chatId);

      const hasEmail = !!user.email;
      const keyboard = isAdminUser ? getAdminKeyboard() : getMainKeyboard(hasEmail);
      
      const cancelMsg = await bot.sendMessage(chatId, `❌ Cancelled`, keyboard);
      
      if (!isAdminUser) {
        trackUserMessage(userId, cancelMsg.message_id);
      }
      
      deleteMessageSafe(chatId, cancelMsg.message_id, 3000);
      return;
    }

    if (data === 'use_default_email') {
      delete awaitingEmailInput[userId];

      if (!isDefaultEmailValid()) {
        const invalidMsg = await bot.sendMessage(chatId,
          `⚠️ Default email is not set or invalid in the environment`,
          { parse_mode: 'Markdown' }
        );
        deleteMessageSafe(chatId, invalidMsg.message_id, 4000);
        return;
      }

      user.email = DEFAULT_USER_EMAIL;
      saveUsers();

      await logActivity(userId, 'email_configured', { email: user.email });

      const hasEmail = !!user.email;
      const keyboard = isAdminUser ? getAdminKeyboard() : getMainKeyboard(hasEmail);

      const confirmMsg = await bot.sendMessage(chatId,
        `✅ Email saved: \`${user.email}\`\n\n` +
        `You can change it anytime via *Change Email*`,
        { parse_mode: 'Markdown', ...keyboard }
      );

      if (!isAdminUser) {
        trackUserMessage(userId, confirmMsg.message_id);
      }

      deleteMessageSafe(chatId, confirmMsg.message_id, 7000);
      return;
    }
    
    // FETCH SIGN-IN CODE
    if (data === 'fetch_signin') {
      if (!user.email) {
        const noEmailMsg = await bot.sendMessage(chatId,
          `⚠️ *EMAIL NOT SET*\n\nSetup email first`,
          { parse_mode: 'Markdown', ...getMainKeyboard(false) }
        );
        deleteMessageSafe(chatId, noEmailMsg.message_id, 5000);
        return;
      }
      
      // Rate limit check
      const rateCheck = checkRateLimit(userId);
      if (!rateCheck.allowed) {
        const rateLimitMsg = await bot.sendMessage(chatId,
          `⏱️ *RATE LIMIT*\n\n` +
          `Max ${MAX_REQUESTS_PER_HOUR} requests/hour\n` +
          `Try again in ${rateCheck.waitMinutes}min`,
          { parse_mode: 'Markdown' }
        );
        deleteMessageSafe(chatId, rateLimitMsg.message_id, 5000);
        return;
      }
      
      if (isUserBusy(userId)) {
        const busyMsg = await bot.sendMessage(chatId, `⏳ Please wait...`);
        deleteMessageSafe(chatId, busyMsg.message_id, 2000);
        return;
      }
      
      await cleanPreviousMessages(userId, chatId);
      setUserBusy(userId);
      
      const loading = await bot.sendMessage(chatId,
        `🔍 Fetching...\n\n📧 \`${user.email}\``,
        { parse_mode: 'Markdown' }
      );
      
      const startTime = Date.now();
      
      try {
        const result = await fetchNetflixEmail(user.email, 'signin');
        
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        
        if (!result || result.type !== 'signin') {
          trackUsage(userId, false, timeTaken);
          
          const notFoundMsg = await bot.sendMessage(chatId,
            `📭 *NO CODE*\n\n` +
            `💡 Request code from Netflix first`,
            {
              parse_mode: 'Markdown',
              reply_markup: {
                inline_keyboard: [
                  [{ text: '🔄 Try', callback_data: 'fetch_signin' }],
                  [{ text: '◀️ Menu', callback_data: 'main_menu' }]
                ]
              }
            }
          );
          
          if (!isAdminUser) {
            trackUserMessage(userId, notFoundMsg.message_id);
          }
          deleteMessageSafe(chatId, notFoundMsg.message_id, 10000);
          
          setUserFree(userId);
          return;
        }
        
        trackUsage(userId, true, timeTaken, result.content, 'signin', result.from, result.folder);
        
        const minutesAgo = Math.floor((Date.now() - result.date.getTime()) / 1000 / 60);
        const timeAgo = minutesAgo > 0 ? `${minutesAgo}m ago` : `now`;
        
        await logActivity(userId, 'fetch_signin_code', {
          signInCode: result.content,
          emailFrom: result.from,
          emailTo: result.to,
          folder: result.folder,
          fetchTime: timeTaken
        });
        
        const finalMsg = await bot.sendMessage(chatId,
          `✅ *SIGN-IN CODE*\n\n` +
          `\`${result.content}\`\n\n` +
          `📂 ${result.folder} • ${timeAgo}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 New', callback_data: 'fetch_signin' }],
                [{ text: '🏠 Household', callback_data: 'fetch_household' }, { text: '🔑 Reset', callback_data: 'fetch_reset' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        if (!isAdminUser) {
          trackUserMessage(userId, finalMsg.message_id);
        }
        
        setUserFree(userId);
        
      } catch (error) {
        console.error('❌ Fetch error:', error);
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        trackUsage(userId, false, timeTaken);
        
        const errorMsg = await bot.sendMessage(chatId,
          `❌ *ERROR*\n\n${getErrorMessage(error)}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 Try', callback_data: 'fetch_signin' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        if (!isAdminUser) {
          trackUserMessage(userId, errorMsg.message_id);
        }
        deleteMessageSafe(chatId, errorMsg.message_id, 8000);
        
        setUserFree(userId);
      }
    }
    
    // FETCH HOUSEHOLD LINK
    if (data === 'fetch_household') {
      if (!user.email) {
        const noEmailMsg = await bot.sendMessage(chatId,
          `⚠️ *EMAIL NOT SET*\n\nSetup email first`,
          { parse_mode: 'Markdown', ...getMainKeyboard(false) }
        );
        deleteMessageSafe(chatId, noEmailMsg.message_id, 5000);
        return;
      }
      
      const rateCheck = checkRateLimit(userId);
      if (!rateCheck.allowed) {
        const rateLimitMsg = await bot.sendMessage(chatId,
          `⏱️ *RATE LIMIT*\n\n` +
          `Max ${MAX_REQUESTS_PER_HOUR} requests/hour\n` +
          `Try again in ${rateCheck.waitMinutes}min`,
          { parse_mode: 'Markdown' }
        );
        deleteMessageSafe(chatId, rateLimitMsg.message_id, 5000);
        return;
      }
      
      if (isUserBusy(userId)) {
        const busyMsg = await bot.sendMessage(chatId, `⏳ Please wait...`);
        deleteMessageSafe(chatId, busyMsg.message_id, 2000);
        return;
      }
      
      await cleanPreviousMessages(userId, chatId);
      setUserBusy(userId);
      
      const loading = await bot.sendMessage(chatId,
        `🔍 Fetching...\n\n📧 \`${user.email}\``,
        { parse_mode: 'Markdown' }
      );
      
      const startTime = Date.now();
      
      try {
        const result = await fetchNetflixEmail(user.email, 'household');
        
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        
        if (!result || result.type !== 'household') {
          trackUsage(userId, false, timeTaken);
          
          const notFoundMsg = await bot.sendMessage(chatId,
            `📭 *NO LINK*\n\n` +
            `💡 Request household access from Netflix`,
            {
              parse_mode: 'Markdown',
              reply_markup: {
                inline_keyboard: [
                  [{ text: '🔄 Try', callback_data: 'fetch_household' }],
                  [{ text: '◀️ Menu', callback_data: 'main_menu' }]
                ]
              }
            }
          );
          
          if (!isAdminUser) {
            trackUserMessage(userId, notFoundMsg.message_id);
          }
          deleteMessageSafe(chatId, notFoundMsg.message_id, 10000);
          
          setUserFree(userId);
          return;
        }
        
        trackUsage(userId, true, timeTaken, result.content, 'household', result.from, result.folder);
        
        const minutesAgo = Math.floor((Date.now() - result.date.getTime()) / 1000 / 60);
        const timeAgo = minutesAgo > 0 ? `${minutesAgo}m ago` : `now`;
        
        await logActivity(userId, 'fetch_household_link', {
          householdLink: result.content,
          emailFrom: result.from,
          emailTo: result.to,
          folder: result.folder,
          fetchTime: timeTaken
        });
        
        const finalMsg = await bot.sendMessage(chatId,
          `✅ *HOUSEHOLD LINK*\n\n` +
          `\`${result.content}\`\n\n` +
          `📂 ${result.folder} • ${timeAgo}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 New', callback_data: 'fetch_household' }],
                [{ text: '📱 Sign-in', callback_data: 'fetch_signin' }, { text: '🔑 Reset', callback_data: 'fetch_reset' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        if (!isAdminUser) {
          trackUserMessage(userId, finalMsg.message_id);
        }
        
        setUserFree(userId);
        
      } catch (error) {
        console.error('❌ Fetch error:', error);
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        trackUsage(userId, false, timeTaken);
        
        const errorMsg = await bot.sendMessage(chatId,
          `❌ *ERROR*\n\n${getErrorMessage(error)}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 Try', callback_data: 'fetch_household' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        if (!isAdminUser) {
          trackUserMessage(userId, errorMsg.message_id);
        }
        deleteMessageSafe(chatId, errorMsg.message_id, 8000);
        
        setUserFree(userId);
      }
    }
    
    // FETCH PASSWORD RESET
    if (data === 'fetch_reset') {
      if (!isAdminUser) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      if (!user.email) {
        const noEmailMsg = await bot.sendMessage(chatId,
          `⚠️ *EMAIL NOT SET*\n\nSetup email first`,
          { parse_mode: 'Markdown', ...getAdminKeyboard() }
        );
        deleteMessageSafe(chatId, noEmailMsg.message_id, 5000);
        return;
      }
      
      if (isUserBusy(userId)) {
        const busyMsg = await bot.sendMessage(chatId, `⏳ Please wait...`);
        deleteMessageSafe(chatId, busyMsg.message_id, 2000);
        return;
      }
      
      setUserBusy(userId);
      
      const loading = await bot.sendMessage(chatId,
        `🔍 Fetching...\n\n📧 \`${user.email}\``,
        { parse_mode: 'Markdown' }
      );
      
      const startTime = Date.now();
      
      try {
        const result = await fetchNetflixEmail(user.email, 'reset');
        
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        
        if (!result || result.type !== 'reset') {
          trackUsage(userId, false, timeTaken);
          
          await bot.sendMessage(chatId,
            `📭 *NO RESET*\n\n` +
            `💡 Request password reset from Netflix`,
            {
              parse_mode: 'Markdown',
              reply_markup: {
                inline_keyboard: [
                  [{ text: '🔄 Try', callback_data: 'fetch_reset' }],
                  [{ text: '◀️ Menu', callback_data: 'main_menu' }]
                ]
              }
            }
          );
          
          setUserFree(userId);
          return;
        }
        
        trackUsage(userId, true, timeTaken, result.content, 'reset', result.from, result.folder);
        
        const minutesAgo = Math.floor((Date.now() - result.date.getTime()) / 1000 / 60);
        const timeAgo = minutesAgo > 0 ? `${minutesAgo}m ago` : `now`;
        
        await logActivity(userId, 'fetch_password_reset', {
          resetLink: result.content,
          emailFrom: result.from,
          emailTo: result.to,
          folder: result.folder,
          fetchTime: timeTaken
        });
        
        await bot.sendMessage(chatId,
          `🔑 *PASSWORD RESET*\n\n` +
          `\`${result.content}\`\n\n` +
          `📂 ${result.folder} • ${timeAgo}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 New', callback_data: 'fetch_reset' }],
                [{ text: '📱 Sign-in', callback_data: 'fetch_signin' }, { text: '🏠 Household', callback_data: 'fetch_household' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        setUserFree(userId);
        
      } catch (error) {
        console.error('❌ Fetch error:', error);
        await deleteMessageSafe(chatId, loading.message_id, 0);
        
        const timeTaken = Math.round((Date.now() - startTime) / 1000);
        trackUsage(userId, false, timeTaken);
        
        await bot.sendMessage(chatId,
          `❌ *ERROR*\n\n${getErrorMessage(error)}`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '🔄 Try', callback_data: 'fetch_reset' }],
                [{ text: '◀️ Menu', callback_data: 'main_menu' }]
              ]
            }
          }
        );
        
        setUserFree(userId);
      }
    }
    
    if (data === 'help') {
      await cleanPreviousMessages(userId, chatId);
      
      const hasEmail = !!user.email;
      
      const helpText = hasEmail ?
        `❓ *HOW TO USE*\n\n` +
        `*Quick:*\n` +
        `1️⃣ Request from Netflix\n` +
        `2️⃣ Click button:\n` +
        `   📱 Sign-in code\n` +
        `   🏠 Household link\n` +
        (isAdminUser ? `   🔑 Password reset\n` : '') +
        `3️⃣ Get it instantly!\n\n` +
        `📧 \`${escapeMarkdown(user.email)}\`\n` +
        `⏱️ Last 30 minutes\n` +
        `⚡ ${MAX_REQUESTS_PER_HOUR} req/hour`
        :
        `❓ *HOW TO USE*\n\n` +
        `*Setup:*\n` +
        `1️⃣ "Setup Email"\n` +
        `2️⃣ Enter email\n` +
        `3️⃣ Request from Netflix\n` +
        `4️⃣ Click button\n` +
        `5️⃣ Get code!`;
      
      const helpMsg = await bot.sendMessage(chatId, helpText, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '◀️ Menu', callback_data: 'main_menu' }]
          ]
        }
      });
      
      if (!isAdminUser) {
        trackUserMessage(userId, helpMsg.message_id);
      }
    }
    
    if (data === 'my_stats') {
      await cleanPreviousMessages(userId, chatId);
      
      const successRate = user.totalRequests > 0
        ? Math.round((user.successfulRequests / user.totalRequests) * 100)
        : 0;
      const safeUser = sanitizeUserForMarkdown(user);

      const statsMsg = await bot.sendMessage(chatId,
        `📊 *YOUR STATS*\n\n` +
        `👤 ${safeUser.fullName}\n` +
        `📧 \`${safeUser.email || 'Not set'}\`\n` +
        `📅 ${new Date(user.addedDate).toLocaleDateString()}\n\n` +
        `*Performance:*\n` +
        `📊 ${user.totalRequests} requests\n` +
        `✅ ${user.successfulRequests} successful\n` +
        `❌ ${user.failedRequests} failed\n` +
        `📈 ${successRate}% success`,
        {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: '◀️ Menu', callback_data: 'main_menu' }]
            ]
          }
        }
      );
      
      if (!isAdminUser) {
        trackUserMessage(userId, statsMsg.message_id);
      }
    }
    
    if (data === 'admin_stats') {
      if (!isAdmin(userId)) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      const totalUsers = Object.keys(authorizedUsers).length;
      const usersWithEmail = Object.values(authorizedUsers).filter(u => u.email).length;
      const successRate = botStats.totalRequests > 0 
        ? Math.round((botStats.successfulRequests / botStats.totalRequests) * 100) 
        : 0;
      
      const uptime = Math.floor((Date.now() - new Date(botStats.startTime).getTime()) / 1000 / 60);
      
      await bot.sendMessage(chatId,
        `📊 *BOT STATISTICS*\n\n` +
        `🤖 ${BOT_NAME} v${BOT_VERSION}\n` +
        `⏰ ${uptime}m uptime\n\n` +
        `*Users:*\n` +
        `👥 ${totalUsers} total\n` +
        `📧 ${usersWithEmail} w/ email\n\n` +
        `*Performance:*\n` +
        `📊 ${botStats.totalRequests} requests\n` +
        `✅ ${botStats.successfulRequests} successful\n` +
        `❌ ${botStats.failedRequests} failed\n` +
        `📈 ${successRate}% rate\n` +
        `⏱️ ${Math.round(botStats.avgFetchTime)}s avg`,
        {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: '👥 Users', callback_data: 'admin_users' }, { text: '📋 Activity', callback_data: 'admin_activity' }],
              [{ text: '🗑️ Cleanup Now', callback_data: 'admin_cleanup' }],
              [{ text: '◀️ Menu', callback_data: 'main_menu' }]
            ]
          }
        }
      );
    }
    
    if (data === 'admin_users') {
      if (!isAdmin(userId)) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      const users = Object.values(authorizedUsers);

      if (users.length === 0) {
        await bot.sendMessage(chatId, '📋 No users', {
          reply_markup: {
            inline_keyboard: [
              [{ text: '◀️ Menu', callback_data: 'main_menu' }]
            ]
          }
        });
        return;
      }

      let listText = `👥 *USERS (${users.length})*\n\n`;

      users.slice(0, 10).forEach((u, i) => {
        const safeUser = sanitizeUserForMarkdown(u);
        listText += `${i + 1}. ${safeUser.fullName}\n`;
        listText += `   🆔 @${safeUser.username}\n`;
        listText += `   📧 \`${safeUser.email}\`\n`;
        listText += `   📊 ${u.totalRequests} req\n\n`;
      });
      
      if (users.length > 10) {
        listText += `... and ${users.length - 10} more`;
      }
      
      await bot.sendMessage(chatId, listText, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '📊 Stats', callback_data: 'admin_stats' }, { text: '📋 Activity', callback_data: 'admin_activity' }],
            [{ text: '◀️ Menu', callback_data: 'main_menu' }]
          ]
        }
      });
    }
    
    if (data === 'admin_activity') {
      if (!isAdmin(userId)) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      if (activityLog.length === 0) {
        await bot.sendMessage(chatId, '📋 No activity', {
          reply_markup: {
            inline_keyboard: [
              [{ text: '◀️ Menu', callback_data: 'main_menu' }]
            ]
          }
        });
        return;
      }
      
      let logText = `📋 *ACTIVITY (10)*\n\n`;

      activityLog.slice(0, 10).forEach((log, i) => {
        const time = new Date(log.timestamp).toISOString().replace('T', ' ').split('.')[0];
        const safeLogUser = sanitizeUserForMarkdown(log);

        logText += `${i + 1}. ${time}\n`;
        logText += `   👤 ${safeLogUser.fullName}\n`;
        logText += `   📧 \`${safeLogUser.email}\`\n`;
        logText += `   📝 ${log.action}\n\n`;
      });
      
      await bot.sendMessage(chatId, logText, {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [
            [{ text: '📊 Stats', callback_data: 'admin_stats' }, { text: '👥 Users', callback_data: 'admin_users' }],
            [{ text: '◀️ Menu', callback_data: 'main_menu' }]
          ]
        }
      });
    }
    
    // ADMIN CLEANUP - MANUAL TRIGGER
    if (data === 'admin_cleanup') {
      if (!isAdmin(userId)) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      await bot.sendMessage(chatId,
        `🗑️ *MANUAL CLEANUP*\n\n` +
        `This will delete data older than ${DATA_RETENTION_DAYS} days.\n\n` +
        `You'll get a report before deletion.\n\n` +
        `Continue?`,
        {
          parse_mode: 'Markdown',
          reply_markup: {
            inline_keyboard: [
              [{ text: '✅ Yes, Clean Now', callback_data: 'confirm_cleanup' }],
              [{ text: '❌ Cancel', callback_data: 'admin_stats' }]
            ]
          }
        }
      );
      return;
    }
    
    if (data === 'confirm_cleanup') {
      if (!isAdmin(userId)) {
        return bot.sendMessage(chatId, '🔒 Admin only!');
      }
      
      await bot.sendMessage(chatId, `🗑️ Running cleanup...`);
      
      await cleanupOldData();
      
      await bot.sendMessage(chatId,
        `✅ Cleanup complete!\n\nCheck report above.`,
        getAdminKeyboard()
      );
      return;
    }
    
    if (data === 'main_menu') {
      await cleanPreviousMessages(userId, chatId);
      
      const hasEmail = !!user.email;
      const keyboard = isAdmin(userId) ? getAdminKeyboard() : getMainKeyboard(hasEmail);
      
      const menuText = hasEmail ?
        `Choose: 👇`
        :
        `⚠️ Setup email first`;
      
      const menuMsg = await bot.sendMessage(chatId, menuText, keyboard);
      
      if (!isAdmin(userId)) {
        trackUserMessage(userId, menuMsg.message_id);
      }
    }
  });

  // EMAIL INPUT HANDLER
  bot.on('message', async (msg) => {
    const text = msg.text || '';
    const userId = msg.from.id.toString();
    const chatId = msg.chat.id;
    
    if (text.startsWith('/')) return;
    
    if (!isAuthorized(userId)) return;
    
    const user = authorizedUsers[userId];
    
    if (awaitingEmailInput[userId]) {
      const email = text.trim();
      
      const validation = isValidEmail(email);
      
      if (!validation.valid) {
        return bot.sendMessage(chatId,
          `❌ *Invalid*\n\n` +
          `${validation.reason}\n\n` +
          `Try again:`,
          {
            parse_mode: 'Markdown',
            reply_markup: {
              inline_keyboard: [
                [{ text: '❌ Cancel', callback_data: 'cancel_email' }]
              ]
            }
          }
        );
      }
      
      user.email = email;
      saveUsers();
      delete awaitingEmailInput[userId];
      
      await logActivity(userId, 'email_configured', { email: email });
      
      await cleanPreviousMessages(userId, chatId);
      
      const isAdminUser = isAdmin(userId);
      const keyboard = isAdminUser ? getAdminKeyboard() : getMainKeyboard(true);
      
      const confirmMsg = await bot.sendMessage(chatId,
        `✅ Email saved: \`${email}\`\n\n` +
        `Choose: 👇`,
        {
          parse_mode: 'Markdown',
          ...keyboard
        }
      );
      
      if (!isAdminUser) {
        trackUserMessage(userId, confirmMsg.message_id);
      }
      
      return;
    }
    
    const isAdminUser = isAdmin(userId);
    const keyboard = isAdminUser ? getAdminKeyboard() : getMainKeyboard(!!user.email);
    
    const buttonsMsg = await bot.sendMessage(chatId, `⚡ Use buttons`, keyboard);
    
    if (!isAdminUser) {
      trackUserMessage(userId, buttonsMsg.message_id);
    }
    
    deleteMessageSafe(chatId, buttonsMsg.message_id, 3000);
  });
}

// ════════════════════════════════════════════════════════════
// GRACEFUL SHUTDOWN
// ════════════════════════════════════════════════════════════

process.on('SIGINT', async () => {
  console.log('\n👋 Shutting down...');
  
  // Send final report to admins before shutdown
  if (ADMIN_USER_IDS.length > 0 && bot) {
    const report = 
      `⚠️ *BOT SHUTDOWN*\n\n` +
      `📅 ${new Date().toISOString().replace('T', ' ').split('.')[0]}\n\n` +
      `*Final Stats:*\n` +
      `📊 ${botStats.totalRequests} total requests\n` +
      `✅ ${botStats.successfulRequests} successful\n` +
      `👥 ${Object.keys(authorizedUsers).length} users`;
    
    for (const adminId of ADMIN_USER_IDS) {
      try {
        await bot.sendMessage(adminId, report, { parse_mode: 'Markdown' });
      } catch (e) {}
    }
  }
  
  if (bot) {
    bot.stopPolling().catch(() => {});
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n👋 Shutting down...');
  if (bot) {
    bot.stopPolling().catch(() => {});
  }
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Exception:', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ Rejection:', reason);
});

// ════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════

loadUsers();
loadStats();
loadActivityLog();
initBot();

console.log(`✅ ${BOT_NAME} v${BOT_VERSION} is ONLINE!`);
console.log(`🚀 Type-specific search: Sign-in / Household / Reset`);
console.log(`🗑️ Auto-cleanup: Every ${DATA_RETENTION_DAYS} days`);
console.log(`📅 Started: ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC`);
console.log('═'.repeat(60) + '\n');
