/* ==========================================================================
   BOLA-Shield AI — System Utilities & Helpers
   ========================================================================== */

/**
 * Display a modern visual toast alert at the bottom right.
 * @param {string} message - Message text
 * @param {string} icon - Emoji icon
 */
export function showToast(message, icon = '🛡️') {
    const toast = document.getElementById('global-alert-toast');
    const toastMsg = document.getElementById('global-toast-message');
    const toastIcon = toast?.querySelector('.toast-icon');

    if (!toast || !toastMsg) return;

    if (toastIcon) toastIcon.innerText = icon;
    toastMsg.innerText = message;
    
    toast.classList.add('show');

    // Automatically remove after 3s
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

/**
 * Log a security entry to the dashboard scrolling console.
 * @param {string} origin - Requester origin (SHIELD, SYSTEM, ALERT, WAF, AUDIT)
 * @param {string} msg - Dynamic log description
 * @param {string} type - Entry styling severity (info, alert, success, warning)
 */
export function logToConsole(origin, msg, type = 'info') {
    const logsBox = document.getElementById('dashboard-console-logs');
    if (!logsBox) return;
    
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];

    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';

    const allowedTypes = new Set(['info', 'alert', 'success', 'warning', 'danger']);
    const safeType = allowedTypes.has(type) ? type : 'info';
    const time = document.createElement('span');
    time.className = 'log-time';
    time.textContent = `${timeStr} [${origin}]`;

    const message = document.createElement('span');
    message.className = `log-msg log-${safeType}`;
    message.textContent = msg;

    logEntry.append(time, message);

    logsBox.appendChild(logEntry);
    
    // Maintain maximum log length to avoid browser lag
    while (logsBox.children.length > 50) {
        logsBox.removeChild(logsBox.firstChild);
    }

    // Scroll to bottom
    logsBox.scrollTop = logsBox.scrollHeight;
}
