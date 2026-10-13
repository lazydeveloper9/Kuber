/* ==========================================================================
   AutoKube — script.js

   All functions referenced by inline handlers in index.html keep their
   original names and signatures:
   toggleTheme, switchView, toggleDropdown, selectCluster, showToast,
   refreshBlockchainData, verifyAuditLog, reanchorAuditLog, resolveAction.

   Backend contract is unchanged:
   GET  /api/snapshot
   GET  /api/blockchain/status | verify-chain | logs?limit=20&offset=0
   GET  /api/compliance/report
   GET  /api/audit/verify/:logId
   POST /api/blockchain/reanchor/:logId
   POST /api/hitl/request/:requestId/resolve   { approved }
   POST /api/actions/resolve                   { target_resource, anomaly_type, action, approved }
   ========================================================================== */
'use strict';

/* ------------------------------------------------------------------ *
 * 0. CONSTANTS, STATE AND SMALL HELPERS
 * ------------------------------------------------------------------ */
const REFRESH_INTERVAL_MS = 30000;
const REQUEST_TIMEOUT_MS = 10000;
const UNDO_WINDOW_MS = 8000;        // time to undo an Approve/Reject before anything is sent
const UNDO_WINDOW_HIGH_MS = 12000;  // longer window for approving HIGH-risk actions
const THEME_STORAGE_KEY = 'autokube-theme';
const BASE_TITLE = document.title;

let isDarkMode = false;
let currentScale = 'high';

let activeIncidents = [];
let usageChartIns = null;
let anomalyChartIns = null;
let terminalLogs = [];
let blockchainRows = [];

let terminalTimer = null;
let terminalSignature = null;
let chartTimer = null;
let chartLayoutKey = '';
let clusterMenuOpen = false;
let clusterMenuTimer = null;
let refreshTimer = null;
let lastRefreshAt = 0;
let dataRequestId = 0;
let isResolving = false; // true while a request is being sent
const pendingActions = new Map(); // card index -> undo-window state
let isRefreshingChain = false;
let chainLoadedOnce = false;

// Demo mode is used only when /api/snapshot is unreachable.
let demoMode = false;
let demoIncidents = null;
const demoAudit = [];

// Remembers per-row verification results so a refresh does not wipe them.
const verifyResults = {};
const recentToasts = new Map();

const $ = (id) => document.getElementById(id);

const prefersReducedMotion = () =>
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[ch]));
}

// Backend text that is allowed to carry light formatting (<strong class="...">, <span class="...">).
// Everything else is reduced to plain text so API data can never inject markup or handlers.
const SAFE_TAGS = new Set(['STRONG', 'B', 'EM', 'I', 'CODE', 'SPAN', 'BR']);
const DROP_TAGS = new Set(['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'TEMPLATE', 'NOSCRIPT']);
const SAFE_CLASS = /^[\w\s\-:/[\].%()#,]*$/;

function sanitizeRichText(html) {
    const tpl = document.createElement('template');
    tpl.innerHTML = String(html ?? '');
    const walk = (node) => {
        Array.from(node.childNodes).forEach((child) => {
            if (child.nodeType === Node.ELEMENT_NODE) {
                if (DROP_TAGS.has(child.tagName)) {
                    child.remove(); // executable/embedded content is discarded with its text
                    return;
                }
                if (!SAFE_TAGS.has(child.tagName)) {
                    child.replaceWith(document.createTextNode(child.textContent));
                    return;
                }
                Array.from(child.attributes).forEach((attr) => {
                    if (!(attr.name === 'class' && SAFE_CLASS.test(attr.value))) {
                        child.removeAttribute(attr.name);
                    }
                });
                walk(child);
            } else if (child.nodeType !== Node.TEXT_NODE) {
                child.remove();
            }
        });
    };
    walk(tpl.content);
    return tpl.innerHTML;
}

function isSafeImageUrl(url) {
    return typeof url === 'string' && /^(https?:\/\/|\/|data:image\/)/i.test(url.trim());
}

function refreshIcons() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        try { window.lucide.createIcons(); } catch (err) { /* icons are decorative; never block the UI */ }
    }
}

function fetchWithTimeout(url, options = {}, timeout = REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
}

// Counts a numeric metric up (or down) to its new value; plain text for non-numeric values.
function setMetric(id, value, format = (n) => String(n)) {
    const el = $(id);
    if (!el) return;

    const target = Number(value);
    if (value === null || value === undefined || value === '' || !Number.isFinite(target)) {
        el.textContent = value ?? '--';
        delete el.dataset.value;
        return;
    }

    const previous = Number(el.dataset.value);
    const from = Number.isFinite(previous) && el.dataset.value !== undefined ? previous : 0;
    el.dataset.value = String(target);

    if (el._tween) cancelAnimationFrame(el._tween);
    if (prefersReducedMotion() || from === target) {
        el.textContent = format(target);
        return;
    }

    const duration = 700;
    const start = performance.now();
    const step = (now) => {
        const t = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - t, 3);
        el.textContent = format(Math.round(from + (target - from) * eased));
        if (t < 1) {
            el._tween = requestAnimationFrame(step);
        } else {
            el._tween = null;
            el.textContent = format(target);
        }
    };
    el._tween = requestAnimationFrame(step);

    el.classList.remove('stat-tick');
    void el.offsetWidth; // restart the CSS animation
    el.classList.add('stat-tick');
}

function emptyStateHtml(icon, title, message) {
    return `
        <div class="glass empty-state p-10 rounded-2xl animate-flip">
            <div class="inline-flex p-3 rounded-full bg-emerald-500/10 mb-4">
                <i data-lucide="${icon}" class="w-6 h-6 text-emerald-500"></i>
            </div>
            <h3 class="font-bold text-base mb-1">${escapeHtml(title)}</h3>
            <p class="text-sm text-theme-muted max-w-sm mx-auto">${escapeHtml(message)}</p>
        </div>`;
}

/* ------------------------------------------------------------------ *
 * 1. THEME LOGIC
 * ------------------------------------------------------------------ */
function applyTheme(dark) {
    isDarkMode = dark;
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');

    const icon = $('theme-icon');
    if (icon) icon.setAttribute('data-lucide', dark ? 'sun' : 'moon');
    const toggle = $('theme-toggle');
    if (toggle) toggle.setAttribute('aria-pressed', String(dark));

    const particles = $('particles-container');
    if (particles) particles.style.display = dark ? 'block' : 'none';

    refreshIcons();
}

function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_STORAGE_KEY); } catch (err) { /* storage unavailable */ }
    applyTheme(saved === 'dark');
}

function toggleTheme() {
    applyTheme(!isDarkMode);
    try { localStorage.setItem(THEME_STORAGE_KEY, isDarkMode ? 'dark' : 'light'); } catch (err) { /* ignore */ }

    // Chart colours depend on the theme, so rebuild them
    if ($('view-dashboard')?.classList.contains('active')) {
        scheduleChartRender(50);
    }
}

function initParticles() {
    const container = $('particles-container');
    if (!container || prefersReducedMotion()) return;
    const fragment = document.createDocumentFragment();
    for (let i = 0; i < 16; i++) {
        const dot = document.createElement('div');
        const size = 3 + Math.random() * 6;
        dot.className = 'particle';
        dot.style.cssText =
            `left:${(Math.random() * 100).toFixed(1)}%;width:${size.toFixed(1)}px;height:${size.toFixed(1)}px;` +
            `animation-duration:${(14 + Math.random() * 14).toFixed(1)}s;animation-delay:-${(Math.random() * 20).toFixed(1)}s;`;
        fragment.appendChild(dot);
    }
    container.appendChild(fragment);
}

/* ------------------------------------------------------------------ *
 * 2. NAVIGATION LOGIC
 * ------------------------------------------------------------------ */
function switchView(id) {
    const target = $('view-' + id);
    if (!target) return;

    document.querySelectorAll('.view-section').forEach((e) => e.classList.remove('active', 'view-enter'));
    document.querySelectorAll('.nav-link').forEach((e) => {
        e.classList.remove('text-blue-500', 'border-b-2', 'border-blue-500');
        e.classList.add('text-theme-muted');
        e.removeAttribute('aria-current');
    });

    target.classList.add('active');
    void target.offsetWidth; // restart the entrance animation on every switch
    target.classList.add('view-enter');

    const navItem = $('nav-' + id);
    if (navItem) {
        navItem.classList.remove('text-theme-muted');
        navItem.classList.add('text-blue-500', 'border-b-2', 'border-blue-500');
        navItem.setAttribute('aria-current', 'page');
    }

    window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });

    // Chart.js cannot measure a hidden canvas, so rebuild when the dashboard comes back
    if (id === 'dashboard') {
        scheduleChartRender(100);
    }
}

/* ------------------------------------------------------------------ *
 * 3. TOAST NOTIFICATION LOGIC
 * ------------------------------------------------------------------ */
function showToast(message, type = 'success', title) {
    const container = $('toast-container');
    if (!container) return;

    // Identical toasts inside 8 seconds are dropped (the 30s refresh could otherwise repeat an error)
    const key = `${type}|${message}`;
    const now = Date.now();
    if (recentToasts.has(key) && now - recentToasts.get(key) < 8000) return;
    recentToasts.set(key, now);

    const isSuccess = type === 'success';
    const toast = document.createElement('div');
    toast.className = `toast-enter toast-item glass p-4 rounded-xl flex items-center gap-3 border-l-4 ${isSuccess ? 'border-l-emerald-500' : 'border-l-red-500'} bg-[var(--toast-bg)] min-w-[300px] shadow-2xl`;
    toast.setAttribute('role', isSuccess ? 'status' : 'alert');
    toast.innerHTML = `
        <div class="p-1.5 rounded-full ${isSuccess ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}">
            <i data-lucide="${isSuccess ? 'check-circle' : 'x-circle'}" class="w-5 h-5"></i>
        </div>
        <div>
            <h4 class="text-sm font-bold"></h4>
            <p class="text-xs text-theme-muted mt-0.5"></p>
        </div>`;
    toast.querySelector('h4').textContent = title || (isSuccess ? 'Action Confirmed' : 'Action Rejected');
    toast.querySelector('p').textContent = message;

    // Keep at most four on screen
    while (container.children.length >= 4) container.firstElementChild.remove();
    container.appendChild(toast);
    refreshIcons();

    let dismissed = false;
    const dismiss = () => {
        if (dismissed) return;
        dismissed = true;
        toast.classList.remove('toast-enter');
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 200);
    };
    toast.addEventListener('click', dismiss);
    let dismissTimer = setTimeout(dismiss, 4000);
    toast.addEventListener('mouseenter', () => clearTimeout(dismissTimer));
    toast.addEventListener('mouseleave', () => { dismissTimer = setTimeout(dismiss, 1500); });
}

/* ------------------------------------------------------------------ *
 * 4. CLUSTER LOGIC
 * ------------------------------------------------------------------ */
const CLUSTER_DOT = {
    emerald: { cls: 'bg-emerald-500', glow: 'rgba(16, 185, 129, 0.6)' },
    yellow: { cls: 'bg-yellow-500', glow: 'rgba(234, 179, 8, 0.6)' },
    blue: { cls: 'bg-blue-500', glow: 'rgba(59, 130, 246, 0.6)' }
};

function setClusterMenu(open) {
    const menu = $('cluster-menu');
    if (!menu) return;
    clearTimeout(clusterMenuTimer);
    clusterMenuOpen = open;
    $('cluster-btn')?.setAttribute('aria-expanded', String(open));

    if (open) {
        menu.classList.remove('hidden');
        clusterMenuTimer = setTimeout(() => {
            menu.classList.remove('opacity-0', '-translate-y-2');
            menu.classList.add('opacity-100', 'translate-y-0');
        }, 10);
    } else {
        menu.classList.remove('opacity-100', 'translate-y-0');
        menu.classList.add('opacity-0', '-translate-y-2');
        clusterMenuTimer = setTimeout(() => menu.classList.add('hidden'), 200);
    }
}

function toggleDropdown() {
    setClusterMenu(!clusterMenuOpen);
}

function selectCluster(name, env, colorClass, scale) {
    setText('selected-cluster-name', name);
    setText('selected-cluster-env', env);

    const palette = CLUSTER_DOT[colorClass] || CLUSTER_DOT.emerald;
    const dot = $('cluster-status-dot');
    if (dot) {
        dot.className = `w-2.5 h-2.5 rounded-full ${palette.cls}`;
        dot.style.boxShadow = `0 0 8px ${palette.glow}`;
    }

    currentScale = scale;
    setClusterMenu(false);

    const terminal = $('terminal-body');
    if (terminal) {
        const line = document.createElement('div');
        line.className = 'animate-flip text-[10px] my-2 text-blue-500 font-bold';
        line.textContent = `$ kubectl config use-context ${name}`;
        terminal.appendChild(line);
        terminal.parentElement.scrollTop = terminal.parentElement.scrollHeight;
    }

    generateData();
    if ($('view-dashboard')?.classList.contains('active')) {
        scheduleChartRender(50);
    }
}

/* ------------------------------------------------------------------ *
 * 5. DATA ENGINE & SCENARIOS
 * ------------------------------------------------------------------ */
const scenarios = [
    {
        target: "payment-service-v3", anomaly: "OOMKilled", blast: "LOW", conf: "98%",
        desc: "Pod terminated by kernel. Memory limit (256Mi) exceeded by 140MB during batch job execution.",
        action: "Patch Deployment: Increase limits.memory to 512Mi. Execute restart.",
        trafficDesc: "Sudden <strong class='text-red-500'>380% spike in ingress traffic</strong> detected at T-5m. This caused the payment queue to saturate, exceeding the allocated memory limit and triggering the kernel to OOMKill the pod to preserve node health.",
        img: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=800"
    },
    {
        target: "cart-redis-cache", anomaly: "CrashLoopBackOff", blast: "LOW", conf: "95%",
        desc: "Pod restarted 6 times in 5m. Fatal error: 'Missing mandatory ENV variable DB_HOST'.",
        action: "Inject DB_HOST from ConfigMap 'redis-config' and rollout deployment.",
        trafficDesc: "Traffic dropped to <strong class='text-blue-500'>zero processing capacity</strong>. Telemetry indicates a configuration drift during the last pipeline deployment caused the pod to continuously crash upon boot sequence.",
        img: "https://images.unsplash.com/photo-1614064641913-a53b51c8af67?auto=format&fit=crop&q=80&w=800"
    },
    {
        target: "frontend-node-04", anomaly: "Node NotReady", blast: "HIGH", conf: "88%",
        desc: "Kubelet reporting high CPU throttling. Node disconnected from control plane.",
        action: "Cordon node, safely evict pods, and provision replacement via AutoScalingGroup.",
        trafficDesc: "A rogue background process caused a <strong class='text-red-500'>100% CPU lockup</strong> on the worker node. The Kubelet became unresponsive, missing health-check heartbeats, leading to a Node NotReady state.",
        img: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&q=80&w=800"
    },
    {
        target: "auth-worker-pod", anomaly: "Pending Pod", blast: "MED", conf: "99%",
        desc: "FailedScheduling: 0/12 nodes are available. No nodes match nodeSelector 'gpu=true'.",
        action: "Provision new NodeGroup with GPU taints, or remove nodeSelector from manifest.",
        trafficDesc: "System scaling attempted to handle normal traffic load, but the scheduler could not find any nodes satisfying the <strong class='text-yellow-600'>hardware requirements (nodeSelector: gpu=true)</strong>, leaving the pod in a pending state.",
        img: "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&q=80&w=800"
    }
];

function buildDemoSnapshot() {
    if (!demoIncidents) {
        demoIncidents = [...scenarios].sort(() => 0.5 - Math.random()).slice(0, 2);
    }
    return {
        metrics: { pods: 0, nodes: 0, anomalies: demoIncidents.length, pending: demoIncidents.length },
        analysis: demoIncidents[0] || {},
        queue: demoIncidents,
        hitl_queue: [],
        terminal_logs: [],
        audit: demoAudit
    };
}

/* ---------------- Blockchain assurance ---------------- */
async function refreshBlockchainData() {
    if (isRefreshingChain) return;
    isRefreshingChain = true;

    const btn = $('bc-refresh-btn');
    if (btn) { btn.classList.add('is-busy'); btn.textContent = 'Refreshing…'; }

    try {
        const [statusRes, chainRes, logsRes, complianceRes] = await Promise.all([
            fetchWithTimeout('/api/blockchain/status', { cache: 'no-store' }),
            fetchWithTimeout('/api/blockchain/verify-chain', { cache: 'no-store' }),
            fetchWithTimeout('/api/blockchain/logs?limit=20&offset=0', { cache: 'no-store' }),
            fetchWithTimeout('/api/compliance/report', { cache: 'no-store' })
        ]);

        if (!statusRes.ok || !chainRes.ok || !logsRes.ok || !complianceRes.ok) {
            throw new Error('Blockchain API call failed');
        }

        const status = await statusRes.json();
        const chain = await chainRes.json();
        const logs = await logsRes.json();
        const compliance = await complianceRes.json();

        const counts = status.anchor_counts || {};
        setMetric('bc-anchored', counts.anchored ?? 0);
        setMetric('bc-pending', counts.pending ?? 0);
        setMetric('bc-failed', counts.failed ?? 0);

        const score = compliance.score || { passed: 0, total: 0 };
        setText('bc-compliance', `${score.passed}/${score.total}`);

        const chainOk = !!(chain.chain && chain.chain.ok);
        const reason = chain.chain?.reason || 'unknown';
        setText('bc-chain-status', chainOk ? 'PASS' : 'FAIL');
        const chainStatusEl = $('bc-chain-status');
        if (chainStatusEl) chainStatusEl.className = `text-lg font-bold ${chainOk ? 'text-emerald-500' : 'text-red-500'}`;
        setText('bc-chain-detail', `Entries: ${chain.entries ?? 0} | Reason: ${reason}`);
        setText('bc-signer-status', status.has_signer_secret
            ? 'Signer: configured'
            : 'Signer: not configured (ephemeral mode allowed if not required)');

        const checksContainer = $('compliance-checks');
        if (checksContainer) {
            const checks = compliance.checks || [];
            checksContainer.innerHTML = checks.map((check) => `
                <div class="flex items-start justify-between gap-3 border border-[var(--panel-border)] rounded-lg p-3">
                    <div>
                        <p class="font-semibold text-sm">${escapeHtml(check.stage)}</p>
                        <p class="text-xs text-theme-muted mt-1">${escapeHtml(check.evidence || '')}</p>
                    </div>
                    <span class="text-[10px] px-2 py-1 rounded-md font-bold ${check.ok ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300' : 'bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-300'}">${check.ok ? 'PASS' : 'FAIL'}</span>
                </div>`).join('');
        }

        const tbody = $('bc-logs-body');
        blockchainRows = Array.isArray(logs.items) ? logs.items : [];
        if (tbody) {
            if (!blockchainRows.length) {
                tbody.innerHTML = `<tr><td colspan="5" class="py-10 px-6 text-center text-xs text-theme-muted font-medium">No logs have been anchored yet. New audit entries appear here once they are recorded.</td></tr>`;
            } else {
                tbody.innerHTML = blockchainRows.map((row) => {
                    const logId = String(row.log_id ?? '');
                    const shortId = logId.slice(0, 10);
                    const tx = row.stellar_receipt ? String(row.stellar_receipt).slice(0, 12) + '...' : '--';
                    const statusClass = row.anchor_status === 'anchored'
                        ? 'text-emerald-500'
                        : row.anchor_status === 'failed'
                            ? 'text-red-500'
                            : 'text-yellow-500';
                    const known = verifyResults[logId];
                    const verifyText = known === undefined ? 'Not checked' : known ? 'PASS' : 'FAIL';
                    const verifyClass = known === undefined
                        ? 'text-xs'
                        : `text-xs font-bold ${known ? 'text-emerald-500' : 'text-red-500'}`;
                    return `
                        <tr class="hover:bg-[var(--hover-bg)] transition-colors">
                            <td class="py-4 px-6 text-xs font-mono">${escapeHtml(shortId)}</td>
                            <td class="py-4 px-6 text-xs font-bold ${statusClass}">${escapeHtml(row.anchor_status || 'pending')}</td>
                            <td class="py-4 px-6 text-xs font-mono text-theme-muted">${escapeHtml(tx)}</td>
                            <td class="py-4 px-6 ${verifyClass}" id="verify-${escapeHtml(logId)}">${verifyText}</td>
                            <td class="py-4 px-6 text-xs flex gap-2">
                                <button type="button" data-action="verify" data-log-id="${escapeHtml(logId)}" class="border border-[var(--panel-border)] px-2 py-1 rounded hover:bg-[var(--hover-bg)]">Verify</button>
                                <button type="button" data-action="reanchor" data-log-id="${escapeHtml(logId)}" class="border border-[var(--panel-border)] px-2 py-1 rounded hover:bg-[var(--hover-bg)]">Re-anchor</button>
                            </td>
                        </tr>`;
                }).join('');
            }
        }

        chainLoadedOnce = true;
        refreshIcons();
    } catch (err) {
        if (!chainLoadedOnce) {
            setText('bc-chain-status', 'Unavailable');
            setText('bc-chain-detail', 'The blockchain service did not respond. Use Refresh to try again.');
        }
        showToast('Unable to load blockchain status.', 'error', 'Connection Issue');
    } finally {
        isRefreshingChain = false;
        if (btn) { btn.classList.remove('is-busy'); btn.textContent = 'Refresh'; }
    }
}

async function verifyAuditLog(logId) {
    const cell = $(`verify-${logId}`);
    if (cell) { cell.textContent = 'Checking…'; cell.className = 'py-4 px-6 text-xs text-theme-muted'; }
    try {
        const res = await fetchWithTimeout(`/api/audit/verify/${encodeURIComponent(logId)}`, { cache: 'no-store' });
        if (!res.ok) throw new Error('Verification failed');
        const body = await res.json();
        const ok = !!(body.local_hash_ok && (body.onchain?.ok ?? true));
        verifyResults[logId] = ok;
        const target = $(`verify-${logId}`);
        if (target) {
            target.textContent = ok ? 'PASS' : 'FAIL';
            target.className = `py-4 px-6 text-xs font-bold ${ok ? 'text-emerald-500' : 'text-red-500'}`;
        }
        showToast(ok ? 'Audit proof verified.' : 'Audit proof check failed.', ok ? 'success' : 'error',
            ok ? 'Proof Verified' : 'Proof Failed');
    } catch (err) {
        const target = $(`verify-${logId}`);
        if (target) { target.textContent = 'Not checked'; target.className = 'py-4 px-6 text-xs'; }
        showToast('Could not verify audit log.', 'error', 'Verification Failed');
    }
}

async function reanchorAuditLog(logId) {
    try {
        const res = await fetchWithTimeout(`/api/blockchain/reanchor/${encodeURIComponent(logId)}`, { method: 'POST' });
        if (!res.ok) throw new Error('Re-anchor failed');
        showToast('Re-anchor request queued.', 'success', 'Re-anchor Queued');
        await refreshBlockchainData();
    } catch (err) {
        showToast('Could not queue re-anchor.', 'error', 'Re-anchor Failed');
    }
}

/* ---------------- Snapshot rendering ---------------- */
function updatePending(pending) {
    setMetric('metric-pending', pending);

    const badge = $('queue-badge');
    if (badge) {
        badge.textContent = pending;
        badge.style.display = pending > 0 ? 'inline-block' : 'none';
    }
    document.title = pending > 0 ? `(${pending}) ${BASE_TITLE}` : BASE_TITLE;
}

function renderMetrics(metrics, pending) {
    setMetric('metric-pods', metrics.pods ?? '--', (n) => n.toLocaleString());
    setMetric('metric-nodes', metrics.nodes ?? '--');
    setMetric('metric-anomalies', metrics.anomalies ?? 0);
    updatePending(pending);
}

function renderAnalysis(analysis) {
    setText('analysis-target', analysis.target || 'No active anomaly');
    setText('analysis-type', analysis.anomaly || 'Healthy');
    setText('analysis-desc', `"${analysis.desc || 'No incidents in latest scan.'}"`);
    setText('analysis-action', analysis.action || 'No action required');
    setText('analysis-conf', analysis.conf || '--');

    const blast = String(analysis.blast || 'LOW');
    setText('analysis-blast', blast);
    const blastEl = $('analysis-blast');
    if (blastEl) {
        const level = blast.toUpperCase();
        blastEl.className = `text-3xl font-black ${level === 'HIGH' ? 'text-red-500' : level === 'MED' ? 'text-yellow-500' : 'text-emerald-500'}`;
    }

    const traffic = $('traffic-explanation');
    if (traffic) traffic.innerHTML = sanitizeRichText(analysis.trafficDesc || 'No active traffic anomaly.');

    const img = $('analysis-img');
    if (img && isSafeImageUrl(analysis.img) && img.getAttribute('src') !== analysis.img) {
        img.style.visibility = '';
        img.src = analysis.img;
    }
}

function renderQueue() {
    const q = $('queue-container');
    if (!q) return;

    if (!activeIncidents.length) {
        q.innerHTML = emptyStateHtml(
            'check-circle',
            'No actions waiting for review',
            'When the Safety Gate pauses an action, it will appear here for your approval.'
        );
        return;
    }

    q.innerHTML = activeIncidents.map((inc, idx) => {
        const isRed = String(inc.blast || '').toUpperCase() === 'HIGH';
        const requestBadge = inc.request_id
            ? `<span class="text-[10px] bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 px-2 py-1 rounded-md font-mono border border-blue-200 dark:border-blue-500/30">HITL: ${escapeHtml(String(inc.request_id).slice(0, 8))}</span>`
            : '';
        return `
            <div id="inc-${idx}" class="glass p-6 rounded-2xl flex flex-col md:flex-row justify-between items-start md:items-center mb-4 gap-4 animate-flip border-l-4 ${isRed ? 'border-l-red-500' : 'border-l-yellow-500'}">
                <div class="flex-1">
                    <div class="flex items-center gap-3 mb-2 flex-wrap">
                        <h3 class="font-bold text-base">${escapeHtml(inc.anomaly || 'Anomaly')}</h3>
                        <span class="text-[10px] bg-[var(--badge-bg)] px-2 py-1 rounded-md font-mono text-theme-muted border border-[var(--panel-border)]">${escapeHtml(inc.target || 'unknown')}</span>
                        ${requestBadge}
                    </div>
                    <p class="text-xs text-theme-muted mb-4 font-medium"><i data-lucide="zap" class="w-3.5 h-3.5 inline text-blue-500"></i> Plan: ${escapeHtml(inc.action || 'Investigate')}</p>
                    <span class="text-[10px] font-bold uppercase tracking-widest ${isRed ? 'text-red-600 bg-red-50 dark:bg-red-500/10' : 'text-yellow-600 bg-yellow-50 dark:bg-yellow-500/10'} px-2.5 py-1.5 rounded-lg">Risk Level: ${escapeHtml(inc.blast || 'MED')}</span>
                </div>
                <div class="flex gap-3 w-full md:w-auto mt-4 md:mt-0">
                    <button type="button" onclick="resolveAction(${idx}, true)" class="flex-1 md:flex-none btn-primary px-6 py-3 rounded-xl text-xs font-bold shadow-md transition-all duration-200">Approve</button>
                    <button type="button" onclick="resolveAction(${idx}, false)" class="flex-1 md:flex-none border border-[var(--panel-border)] hover:bg-[var(--hover-bg)] px-6 py-3 rounded-xl text-xs font-bold transition-all duration-200">Reject</button>
                </div>
            </div>`;
    }).join('');
}

function renderAudit(rows) {
    const audit = $('audit-table-body');
    if (!audit) return;

    if (!rows.length) {
        audit.innerHTML = `<tr><td colspan="5" class="py-10 px-6 text-center text-xs text-theme-muted font-medium">No actions recorded yet. Approved and automated actions will appear here.</td></tr>`;
        return;
    }

    audit.innerHTML = rows.map((row) => {
        const date = row.timestamp ? new Date(row.timestamp) : new Date();
        const ts = Number.isNaN(date.getTime()) ? '--' : date.toLocaleTimeString();
        const incident = row.incident_summary || 'N/A';
        const action = row.action_taken || 'N/A';
        const approved = row.human_approved === true;
        return `
            <tr class="hover:bg-[var(--hover-bg)] transition-colors">
                <td class="py-4 px-6 text-xs font-mono text-theme-muted">${escapeHtml(ts)}</td>
                <td class="py-4 px-6 font-mono text-xs font-bold text-blue-600 dark:text-blue-400 whitespace-normal break-words max-w-[320px]">${escapeHtml(incident)}</td>
                <td class="py-4 px-6 text-xs font-bold ${approved ? 'text-emerald-500' : 'text-yellow-600 dark:text-yellow-500'}">${approved ? 'Approved' : 'Rejected/Auto'}</td>
                <td class="py-4 px-6 text-xs text-theme-muted truncate max-w-[250px] font-medium" title="${escapeHtml(action)}">${escapeHtml(action)}</td>
                <td class="py-4 px-6"><span class="${approved ? 'bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300 border-blue-200 dark:border-blue-500/30' : 'bg-amber-100 text-amber-700 dark:bg-amber-500/20 dark:text-amber-300 border-amber-200 dark:border-amber-500/30'} border px-2 py-1 rounded text-[10px] font-bold tracking-wide">${approved ? 'HUMAN APPROVED' : 'NO APPROVAL'}</span></td>
            </tr>`;
    }).join('');
}

function renderSnapshot(data) {
    const metrics = data.metrics || {};
    const analysis = data.analysis || {};
    const hitlQueue = Array.isArray(data.hitl_queue) ? data.hitl_queue : [];
    const anomalyQueue = Array.isArray(data.queue) ? data.queue : [];

    activeIncidents = hitlQueue.length ? hitlQueue : anomalyQueue;
    terminalLogs = Array.isArray(data.terminal_logs) ? data.terminal_logs : [];

    const pending = metrics.pending ?? activeIncidents.length;
    renderMetrics(metrics, pending);
    renderAnalysis(analysis);
    renderQueue();
    renderAudit(Array.isArray(data.audit) ? data.audit : []);
    refreshIcons();
}

async function generateData() {
    // never rebuild the queue while an approval is counting down or being sent
    if (isResolving || pendingActions.size) return;
    const requestId = ++dataRequestId;

    let data = null;
    try {
        const res = await fetchWithTimeout('/api/snapshot', { cache: 'no-store' });
        if (!res.ok) throw new Error('Snapshot API failed');
        data = await res.json();
    } catch (err) {
        data = null;
    }
    if (requestId !== dataRequestId) return; // a newer request superseded this one

    demoMode = data === null;
    try {
        renderSnapshot(data || buildDemoSnapshot());
    } catch (err) {
        console.error('AutoKube: failed to render snapshot', err);
        showToast('The latest data could not be displayed.', 'error', 'Display Error');
        return;
    }
    if (demoMode) {
        showToast('Backend unavailable. Showing demo data.', 'error', 'Connection Issue');
    }

    runTerminal();
    if (chartKey() !== chartLayoutKey && $('view-dashboard')?.classList.contains('active')) {
        scheduleChartRender(50);
    }
}

/* ------------------------------------------------------------------ *
 * 6. CHARTS (SPA safe)
 * ------------------------------------------------------------------ */
function chartKey() {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const narrow = window.matchMedia && window.matchMedia('(max-width: 640px)').matches;
    return `${activeIncidents[0]?.anomaly || 'None'}|${dark}|${narrow}`;
}

function destroyCharts() {
    if (usageChartIns) { usageChartIns.destroy(); usageChartIns = null; }
    if (anomalyChartIns) { anomalyChartIns.destroy(); anomalyChartIns = null; }
}

function scheduleChartRender(delay = 50) {
    clearTimeout(chartTimer);
    destroyCharts();
    chartTimer = setTimeout(renderCharts, delay);
}

function renderCharts() {
    if (!$('view-dashboard')?.classList.contains('active')) return;
    if (typeof Chart === 'undefined') return; // Chart.js failed to load; the rest of the page still works

    destroyCharts();

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#a1a1aa' : '#64748b';
    const gridColor = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)';
    const narrow = window.matchMedia && window.matchMedia('(max-width: 640px)').matches;
    const animation = prefersReducedMotion() ? false : { duration: 900, easing: 'easeOutQuart' };
    const tooltip = {
        mode: 'index',
        intersect: false,
        backgroundColor: isDark ? '#18181b' : '#ffffff',
        titleColor: isDark ? '#fafafa' : '#0f172a',
        bodyColor: textColor,
        borderColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)',
        borderWidth: 1
    };

    const mainAnomaly = activeIncidents[0]?.anomaly || 'None';
    let cpuData, memData;

    if (mainAnomaly === 'OOMKilled') {
        cpuData = [30, 32, 35, 33, 40, 42, 0];
        memData = [40, 45, 50, 70, 95, 100, 0];
    } else if (mainAnomaly === 'Node NotReady') {
        cpuData = [40, 45, 60, 85, 100, 100, 0];
        memData = [30, 32, 33, 35, 38, 40, 0];
    } else {
        cpuData = [20, 45, 10, 80, 20, 90, 0];
        memData = [50, 50, 50, 50, 50, 50, 0];
    }

    const ctxUsage = $('usageChart');
    if (!ctxUsage) return;
    const ctx2d = ctxUsage.getContext('2d');

    const gradientCpu = ctx2d.createLinearGradient(0, 0, 0, 300);
    gradientCpu.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
    gradientCpu.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

    const gradientMem = ctx2d.createLinearGradient(0, 0, 0, 300);
    gradientMem.addColorStop(0, 'rgba(16, 185, 129, 0.4)');
    gradientMem.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

    usageChartIns = new Chart(ctx2d, {
        type: 'line',
        data: {
            labels: ['-30m', '-25m', '-20m', '-15m', '-10m', '-5m', 'Now'],
            datasets: [
                { label: 'CPU %', data: cpuData, borderColor: '#3b82f6', backgroundColor: gradientCpu, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 2 },
                { label: 'Mem %', data: memData, borderColor: '#10b981', backgroundColor: gradientMem, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 2 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false, // keeps the canvas sized to its wrapper inside tabs
            animation,
            color: textColor,
            scales: {
                x: { grid: { display: false }, ticks: { color: textColor, font: { size: 10 } } },
                y: { min: 0, max: 100, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
            },
            plugins: { legend: { display: false }, tooltip },
            interaction: { mode: 'nearest', axis: 'x', intersect: false }
        }
    });

    const ctxAnom = $('anomalyChart');
    if (!ctxAnom) return;
    anomalyChartIns = new Chart(ctxAnom.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['CrashLoop', 'OOMKilled', 'Pending', 'Evicted'],
            datasets: [{ data: [35, 25, 15, 5], backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6'], borderWidth: 0, hoverOffset: 4 }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation,
            color: textColor,
            plugins: {
                legend: { position: narrow ? 'bottom' : 'right', labels: { color: textColor, boxWidth: 10, font: { size: 11, family: 'Inter' } } },
                tooltip: { ...tooltip, mode: 'nearest' }
            },
            cutout: '75%'
        }
    });

    chartLayoutKey = chartKey();
}

/* ------------------------------------------------------------------ *
 * 7. TERMINAL & ACTION RESOLUTION
 * ------------------------------------------------------------------ */
function buildTerminalLogs() {
    if (terminalLogs.length) return terminalLogs;

    const anomaly = activeIncidents[0]?.anomaly;
    if (!anomaly) {
        return [
            `<span class="text-blue-500">> [Observe]</span> Pulling cluster state via MCP...`,
            `<span class="text-emerald-500">> [Detect]</span> No anomalies found. Cluster is healthy.`
        ];
    }
    return [
        `<span class="text-blue-500">> [Observe]</span> Pulling cluster state via MCP...`,
        `<span class="text-yellow-600 dark:text-yellow-500">> [Detect]</span> Anomaly isolated: ${escapeHtml(anomaly)}.`,
        `<span class="text-purple-500">> [Diagnose]</span> Chunking and extracting logs...`,
        `<span class="text-emerald-500">> [Plan]</span> Remediation synthesized. Blast radius evaluated.`,
        `<span class="text-red-500 font-bold">⚠ [Safety Gate]</span> Execution halted. State change requires Human-in-the-Loop approval.`
    ];
}

// Replays the pipeline only when its content changes, so the 30-second refresh does not
// restart the animation (or erase a "kubectl config use-context" line) for no reason.
function runTerminal(force = false) {
    const t = $('terminal-body');
    if (!t) return;

    const logs = buildTerminalLogs();
    const signature = JSON.stringify(logs);
    if (!force && signature === terminalSignature) return;
    terminalSignature = signature;

    clearInterval(terminalTimer);
    t.innerHTML = `<p class="mb-3 text-theme-muted font-bold tracking-widest uppercase text-[10px] border-b border-[var(--panel-border)] pb-2 inline-block">LangGraph Pipeline Initialized</p>`;

    let i = 0;
    const addLine = () => {
        const line = document.createElement('div');
        line.className = 'animate-flip my-2';
        line.innerHTML = sanitizeRichText(logs[i]);
        t.appendChild(line);
        t.parentElement.scrollTop = t.parentElement.scrollHeight;
        i++;
    };

    if (prefersReducedMotion()) {
        while (i < logs.length) addLine();
        return;
    }

    terminalTimer = setInterval(() => {
        if (i < logs.length) {
            addLine();
        } else {
            clearInterval(terminalTimer);
            terminalTimer = null;
        }
    }, 800);
}

// Safer approvals: Approve/Reject first opens an undo window. The request is only sent when the
// countdown ends or the reviewer chooses "Send now"; Undo restores the card with nothing sent.
function resolveAction(idx, isApproved) {
    if (pendingActions.has(idx)) return;
    const inc = activeIncidents[idx];
    const card = $('inc-' + idx);
    const controls = card?.querySelector('button')?.parentElement;
    if (!inc || !card || !controls) return;

    const targetName = inc.target || 'unknown';
    const highRisk = String(inc.blast || '').toUpperCase() === 'HIGH';
    const windowMs = isApproved && highRisk ? UNDO_WINDOW_HIGH_MS : UNDO_WINDOW_MS;
    const verb = isApproved ? 'Approving' : 'Rejecting';
    const endsAt = Date.now() + windowMs;

    const state = { controls, originalControls: controls.innerHTML, timer: null, tick: null };
    pendingActions.set(idx, state);

    card.classList.add('undo-pending');
    controls.innerHTML = `
        <div class="undo-panel w-full md:w-72" role="group" aria-label="${verb} countdown">
            <div class="flex items-center justify-between gap-3 mb-2">
                <span class="text-xs font-bold" data-undo-label></span>
                <div class="flex gap-2">
                    <button type="button" data-undo class="border border-[var(--panel-border)] hover:bg-[var(--hover-bg)] px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200">Undo</button>
                    <button type="button" data-send-now class="btn-primary px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200">Send now</button>
                </div>
            </div>
            <div class="undo-bar" aria-hidden="true"><span style="--undo-ms:${windowMs}ms"></span></div>
        </div>`;

    const label = controls.querySelector('[data-undo-label]');
    const updateLabel = () => {
        const secs = Math.max(0, Math.ceil((endsAt - Date.now()) / 1000));
        label.textContent = `${verb} in ${secs}s`;
    };
    updateLabel();

    const stopTimers = () => { clearTimeout(state.timer); clearInterval(state.tick); };
    state.tick = setInterval(updateLabel, 250);
    state.timer = setTimeout(() => { stopTimers(); commitAction(idx, isApproved, state); }, windowMs);

    const undoBtn = controls.querySelector('[data-undo]');
    undoBtn.addEventListener('click', () => {
        stopTimers();
        pendingActions.delete(idx);
        card.classList.remove('undo-pending');
        controls.innerHTML = state.originalControls;
        controls.querySelector('button')?.focus();
        showToast(`${targetName}: nothing was sent.`, 'success', 'Action Undone');
    });
    controls.querySelector('[data-send-now]').addEventListener('click', () => {
        stopTimers();
        commitAction(idx, isApproved, state);
    });
    undoBtn.focus();
}

// Sends the decision once the undo window has closed.
async function commitAction(idx, isApproved, state) {
    const inc = activeIncidents[idx];
    const card = $('inc-' + idx);
    if (!inc || !card) {
        pendingActions.delete(idx);
        return;
    }
    const targetName = inc.target || 'unknown';
    const actionDesc = inc.action || 'Investigate';

    card.classList.remove('undo-pending');
    state.controls.innerHTML = `<span class="inline-flex items-center gap-2 px-4 py-3 text-xs font-bold"><i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> ${isApproved ? 'Executing...' : 'Rejecting...'}</span>`;
    refreshIcons();

    while (isResolving) await wait(50); // decisions are sent one at a time
    isResolving = true;

    let sent = true;
    if (demoMode) {
        await wait(450); // no backend in demo mode: resolve locally
    } else {
        try {
            let res;
            if (inc.request_id) {
                res = await fetchWithTimeout(`/api/hitl/request/${encodeURIComponent(inc.request_id)}/resolve`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ approved: isApproved })
                });
            } else {
                res = await fetchWithTimeout('/api/actions/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target_resource: targetName,
                        anomaly_type: inc.anomaly,
                        action: actionDesc,
                        approved: isApproved
                    })
                });
            }
            if (!res.ok) throw new Error('HTTP ' + res.status);
        } catch (err) {
            sent = false;
        }
    }

    if (!sent) {
        // Keep the card so the reviewer can retry instead of losing the request
        state.controls.innerHTML = state.originalControls;
        isResolving = false;
        pendingActions.delete(idx);
        showToast('Failed to send action to backend.', 'error', 'Action Failed');
        return;
    }

    // The backend now processes the action via BackgroundTasks, so fade the card out
    card.style.transition = 'opacity 200ms ease, transform 200ms ease';
    card.style.opacity = '0';
    card.style.transform = 'translateY(-6px)';
    setTimeout(() => { card.style.display = 'none'; }, 200);

    const badge = $('queue-badge');
    let remaining = parseInt(badge?.textContent, 10);
    if (!Number.isFinite(remaining)) remaining = activeIncidents.length;
    remaining = Math.max(0, remaining - 1);
    updatePending(remaining);

    if (demoMode) {
        demoIncidents = (demoIncidents || []).filter((item) => item !== inc);
        demoAudit.unshift({
            timestamp: new Date().toISOString(),
            incident_summary: targetName,
            action_taken: actionDesc,
            human_approved: isApproved
        });
    }

    if (isApproved) {
        showToast(`Execution started in background for ${targetName}...`, 'success', 'Action Confirmed');

        if (!demoMode) {
            // Optimistic audit-trail row until the next refresh returns the stored record
            const audit = $('audit-table-body');
            if (audit) {
                if (audit.querySelector('td[colspan]')) audit.innerHTML = '';
                const newRow = document.createElement('tr');
                newRow.className = 'hover:bg-[var(--hover-bg)] transition-colors animate-flip bg-emerald-50 dark:bg-emerald-500/5';
                newRow.innerHTML = `
                    <td class="py-4 px-6 text-xs font-mono text-theme-muted">${escapeHtml(new Date().toLocaleTimeString())}</td>
                    <td class="py-4 px-6 font-mono text-xs font-bold text-[var(--text-main)] whitespace-normal break-words max-w-[320px]">${escapeHtml(targetName)}</td>
                    <td class="py-4 px-6 text-xs font-bold text-emerald-600 dark:text-emerald-500">Executing (Background)</td>
                    <td class="py-4 px-6 text-xs text-theme-muted truncate max-w-[250px] font-medium">${escapeHtml(actionDesc)}</td>
                    <td class="py-4 px-6"><span class="bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300 border border-blue-200 dark:border-blue-500/30 px-2 py-1 rounded text-[10px] font-bold tracking-wide">HUMAN OVERRIDE</span></td>`;
                audit.insertBefore(newRow, audit.firstChild);
            }
        }
    } else {
        showToast(`Agent halted. ${targetName} escalated to manual team.`, 'error', 'Action Rejected');
    }

    isResolving = false;
    pendingActions.delete(idx); // released last, so a refresh cannot rebuild cards that are still waiting
    await generateData();
}

/* ------------------------------------------------------------------ *
 * 8. EVENT WIRING & START-UP
 * ------------------------------------------------------------------ */
function enhanceInteractiveElements() {
    // onclick-driven <div>/<span> controls become keyboard-reachable buttons
    document.querySelectorAll('[onclick]').forEach((el) => {
        if (el.matches('button, a, input, select, textarea')) return;
        if (!el.hasAttribute('role')) el.setAttribute('role', 'button');
        if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    });
}

function bindEvents() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && clusterMenuOpen) {
            setClusterMenu(false);
            $('cluster-btn')?.focus();
            return;
        }
        if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('[role="button"][onclick]')) {
            e.preventDefault();
            e.target.click();
        }
    });

    // Close the cluster menu when clicking anywhere outside it
    document.addEventListener('click', (e) => {
        if (clusterMenuOpen && !e.target.closest('#cluster-btn, #cluster-menu')) {
            setClusterMenu(false);
        }
    });

    // Blockchain row actions (event delegation keeps row markup free of inline handlers)
    $('bc-logs-body')?.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const logId = btn.getAttribute('data-log-id');
        if (btn.dataset.action === 'verify') verifyAuditLog(logId);
        if (btn.dataset.action === 'reanchor') reanchorAuditLog(logId);
    });

    // Diagnostic image: hide it cleanly if the remote URL fails
    $('analysis-img')?.addEventListener('error', (e) => {
        if (e.target.getAttribute('src')?.startsWith('data:')) return;
        e.target.style.visibility = 'hidden';
    });

    // Rebuild charts when the viewport crosses the mobile breakpoint (legend position changes)
    let resizeTimer = null;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if ($('view-dashboard')?.classList.contains('active') && chartKey() !== chartLayoutKey) {
                scheduleChartRender(50);
            }
        }, 200);
    });

    // Pause background polling while the tab is hidden; catch up when it returns
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && Date.now() - lastRefreshAt > 10000) refreshAll();
    });

    // A decision still inside its undo window has not been sent yet; warn before the tab closes
    window.addEventListener('beforeunload', (e) => {
        if (pendingActions.size || isResolving) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    window.addEventListener('unhandledrejection', (e) => {
        console.error('AutoKube: unhandled promise rejection', e.reason);
    });
}

async function refreshAll() {
    lastRefreshAt = Date.now();
    await Promise.allSettled([generateData(), refreshBlockchainData()]);
}

async function initApp() {
    initTheme();
    initParticles();
    enhanceInteractiveElements();
    bindEvents();
    refreshIcons();

    await refreshAll();
    scheduleChartRender(150);

    refreshTimer = setInterval(() => {
        if (!document.hidden) refreshAll();
    }, REFRESH_INTERVAL_MS);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
