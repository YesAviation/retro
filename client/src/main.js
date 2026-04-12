/**
 * Retro — UI Application
 *
 * Desktop GUI with sidebar navigation, direct connect,
 * chat view, and settings panel.
 *
 * Communicates with the Tauri Rust backend via IPC.
 * All encryption/decryption happens in the Rust backend.
 */

// ─── DOM Elements ───────────────────────────────────────────────────────────

// Sidebar
const sidebarNav = document.getElementById("sidebar-nav");
const sidebarRoomSection = document.getElementById("sidebar-room-section");
const roomInfoEl = document.getElementById("room-info");
const memberListEl = document.getElementById("member-list");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const settingsBtn = document.getElementById("settings-btn");
const btnSession = document.getElementById("btn-session");
const btnSessionLabel = document.getElementById("btn-session-label");

// Views
const views = {
    home: document.getElementById("view-home"),
    chat: document.getElementById("view-chat"),
    lobby: document.getElementById("view-lobby"),
    settings: document.getElementById("view-settings"),
};

// Direct connect (now a modal)
const btnDirectConnect = document.getElementById("btn-direct-connect");
const dcHost = document.getElementById("dc-host");
const dcPort = document.getElementById("dc-port");
const dcConnectBtn = document.getElementById("dc-connect-btn");

// Chat
const chatRoomName = document.getElementById("chat-room-name");
const chatRoomAge = document.getElementById("chat-room-age");
const messagesEl = document.getElementById("messages");
const chatInput = document.getElementById("chat-input");
const btnSend = document.getElementById("btn-send");
const btnLeaveRoom = document.getElementById("btn-leave-room");
const btnCloseRoom = document.getElementById("btn-close-room");

// Lobby
const lobbyServerName = document.getElementById("lobby-server-name");
const lobbyHandle = document.getElementById("lobby-handle");
const createRoomName = document.getElementById("create-room-name");
const btnCreateRoom = document.getElementById("btn-create-room");
const createRoomPasswordToggle = document.getElementById("create-room-password-toggle");
const createRoomPassword = document.getElementById("create-room-password");
const createRoomHidden = document.getElementById("create-room-hidden");
const joinRoomId = document.getElementById("join-room-id");
const btnJoinRoom = document.getElementById("btn-join-room");
const joinRoomPassword = document.getElementById("join-room-password");
const btnDisconnect = document.getElementById("btn-disconnect");
const lobbyRoomList = document.getElementById("lobby-room-list");
const btnRefreshRooms = document.getElementById("btn-refresh-rooms");

// Theme
const themeToggles = document.querySelectorAll(".toggle-opt[data-theme]");

// Modal
const modalOverlay = document.getElementById("modal-overlay");
const modalTitle = document.getElementById("modal-title");
const modalBody = document.getElementById("modal-body");
const modalClose = document.getElementById("modal-close");

// Settings — Language
const languageSelect = document.getElementById("language-select");

// Settings — Accessibility
const fontSizeToggles = document.querySelectorAll(".toggle-opt[data-fontsize]");
const reducedMotionToggle = document.getElementById("reduced-motion-toggle");

// Screen reader announcements
const srAnnouncements = document.getElementById("sr-announcements");
const srErrors = document.getElementById("sr-errors");

// Settings — High Contrast
const highContrastToggle = document.getElementById("high-contrast-toggle");

// ─── State ──────────────────────────────────────────────────────────────────

const state = {
    handle: null,
    currentRoom: null,
    currentRoomName: null,
    connected: false,
    serverAddress: null,
    members: [],
    currentView: "home",
    isCreator: false,
    roomCreatedAt: null,
    ageTimer: null,
};

// ─── Screen Reader Announcements ────────────────────────────────────────────

function announce(message) {
    if (srAnnouncements) {
        srAnnouncements.textContent = message;
    }
}

/** Assertive announcement for errors — interrupts screen reader */
function announceError(message) {
    if (srErrors) {
        srErrors.textContent = "";
        // Force re-announcement by clearing then setting in next frame
        requestAnimationFrame(() => { srErrors.textContent = message; });
    }
}

// ─── HTML Escaping ──────────────────────────────────────────────────────────

/** Escape a string for safe insertion into HTML. Prevents XSS. */
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = String(text);
    return div.innerHTML;
}

// ─── View Management ────────────────────────────────────────────────────────

function showView(viewName) {
    // Hide all views
    Object.values(views).forEach((v) => v.classList.remove("active"));

    // Show target view
    const target = views[viewName];
    if (target) {
        target.classList.add("active");
    }

    // Update nav button active state
    sidebarNav.querySelectorAll(".nav-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.view === viewName);
    });

    // Settings button active state
    settingsBtn.classList.toggle("active", viewName === "settings");

    // Session button active state
    btnSession.classList.toggle("active", viewName === "lobby" || viewName === "chat");

    state.currentView = viewName;

    if (viewName === "lobby") listRooms();

    // Move focus to the new view's heading for screen reader users
    const activeView = views[viewName];
    if (activeView) {
        const heading = activeView.querySelector("h2, #chat-room-name");
        if (heading) {
            heading.setAttribute("tabindex", "-1");
            heading.focus({ preventScroll: true });
        }
    }
}

// ─── Theme ──────────────────────────────────────────────────────────────────

function setTheme(theme) {
    const root = document.documentElement;
    root.classList.remove("theme-dark", "theme-light");
    root.classList.add(`theme-${theme}`);

    // Update toggle buttons
    themeToggles.forEach((btn) => {
        const isActive = btn.dataset.theme === theme;
        btn.classList.toggle("active", isActive);
        btn.setAttribute("aria-checked", isActive ? "true" : "false");
    });

    localStorage.setItem("retro-theme", theme);
}

function loadTheme() {
    const saved = localStorage.getItem("retro-theme");
    setTheme(saved || "dark");
}

// ─── Font Size ──────────────────────────────────────────────────────────────

function setFontSize(size) {
    const root = document.documentElement;
    root.classList.remove("font-small", "font-medium", "font-large");
    root.classList.add(`font-${size}`);

    fontSizeToggles.forEach((btn) => {
        const isActive = btn.dataset.fontsize === size;
        btn.classList.toggle("active", isActive);
        btn.setAttribute("aria-checked", isActive ? "true" : "false");
    });

    localStorage.setItem("retro-font-size", size);
}

function loadFontSize() {
    const saved = localStorage.getItem("retro-font-size");
    setFontSize(saved || "medium");
}

// ─── Reduced Motion ─────────────────────────────────────────────────────────

function setReducedMotion(enabled) {
    const root = document.documentElement;
    if (enabled) {
        root.classList.add("reduced-motion");
    } else {
        root.classList.remove("reduced-motion");
    }
    reducedMotionToggle.checked = enabled;
    localStorage.setItem("retro-reduced-motion", enabled ? "1" : "0");
}

function loadReducedMotion() {
    const saved = localStorage.getItem("retro-reduced-motion");
    // Respect OS preference if no saved setting
    if (saved === null) {
        const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        setReducedMotion(prefersReduced);
    } else {
        setReducedMotion(saved === "1");
    }
}

// ─── High Contrast ─────────────────────────────────────────────────────

function setHighContrast(enabled) {
    const root = document.documentElement;
    if (enabled) {
        root.classList.add("high-contrast");
    } else {
        root.classList.remove("high-contrast");
    }
    highContrastToggle.checked = enabled;
    localStorage.setItem("retro-high-contrast", enabled ? "1" : "0");
}

function loadHighContrast() {
    const saved = localStorage.getItem("retro-high-contrast");
    if (saved === null) {
        const prefersContrast = window.matchMedia("(prefers-contrast: more)").matches;
        setHighContrast(prefersContrast);
    } else {
        setHighContrast(saved === "1");
    }
}

// ─── Language ───────────────────────────────────────────────────────────────

function populateLanguageSelect() {
    const locales = i18n.getSupportedLocales();
    languageSelect.innerHTML = "";

    Object.entries(locales).forEach(([code, name]) => {
        const option = document.createElement("option");
        option.value = code;
        option.textContent = name;
        languageSelect.appendChild(option);
    });

    languageSelect.value = i18n.getLocale();
}

// ─── Connection Status ──────────────────────────────────────────────────────

function updateConnectionStatus() {
    if (state.connected) {
        statusDot.className = "dot-connected";
        statusText.textContent = state.serverAddress || i18n.t("status.connected");
    } else {
        statusDot.className = "dot-disconnected";
        statusText.textContent = i18n.t("status.not_connected");
    }
    updateSessionButton();
}

function updateSessionButton() {
    if (!state.connected) {
        btnSession.classList.add("hidden");
        return;
    }
    btnSession.classList.remove("hidden");
    if (state.currentRoom) {
        btnSessionLabel.textContent = i18n.t("chat.session_chat");
    } else {
        btnSessionLabel.textContent = i18n.t("chat.session_lobby");
    }
}

// ─── Sidebar Room Section ───────────────────────────────────────────────────

function updateRoomSection() {
    if (state.currentRoom) {
        sidebarRoomSection.classList.remove("hidden");
        roomInfoEl.textContent = state.currentRoomName || state.currentRoom.substring(0, 16);
        updateMemberList();
    } else {
        sidebarRoomSection.classList.add("hidden");
    }
    updateSessionButton();
}

function updateMemberList() {
    memberListEl.innerHTML = "";
    state.members.forEach((member) => {
        const li = document.createElement("li");
        const handleSpan = document.createElement("span");
        handleSpan.className = "member-handle";
        handleSpan.textContent = member.handle;
        li.appendChild(handleSpan);

        if (member.handle === state.handle) {
            const youSpan = document.createElement("span");
            youSpan.className = "member-you";
            youSpan.textContent = " " + i18n.t("chat.you");
            li.appendChild(youSpan);
        }

        memberListEl.appendChild(li);
    });
}

// ─── Chat Messages ──────────────────────────────────────────────────────────

function addMessage(handle, text) {
    const div = document.createElement("div");
    div.className = "msg";
    div.setAttribute("role", "listitem");
    div.setAttribute("aria-label", `${handle}: ${text}`);

    const h = document.createElement("span");
    h.className = "msg-handle";
    h.textContent = `${handle} `;
    h.setAttribute("aria-hidden", "true");

    const t = document.createElement("span");
    t.className = "msg-text";
    t.textContent = text;
    t.setAttribute("aria-hidden", "true");

    div.appendChild(h);
    div.appendChild(t);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addDM(from, text, outgoing) {
    const div = document.createElement("div");
    div.className = "msg msg-dm";
    div.setAttribute("role", "listitem");
    const dmLabel = outgoing
        ? i18n.t("chat.dm_to", { handle: from })
        : i18n.t("chat.dm_from", { handle: from });
    div.setAttribute("aria-label", `${dmLabel}${text}`);

    const label = document.createElement("span");
    label.className = "msg-label";
    label.textContent = dmLabel;
    label.setAttribute("aria-hidden", "true");

    const t = document.createElement("span");
    t.textContent = text;
    t.setAttribute("aria-hidden", "true");

    div.appendChild(label);
    div.appendChild(t);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addSystemMessage(text) {
    const div = document.createElement("div");
    div.className = "msg msg-system";
    div.setAttribute("role", "listitem");
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addErrorMessage(text) {
    const div = document.createElement("div");
    div.className = "msg msg-error";
    div.setAttribute("role", "listitem");
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    announceError(text);
}

// ─── Room Age & Close Button ────────────────────────────────────────────────

function updateCloseButton() {
    if (state.isCreator) {
        btnCloseRoom.classList.remove("hidden");
    } else {
        btnCloseRoom.classList.add("hidden");
    }
}

function formatAge(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    if (hrs < 24) return `${hrs}h ${remMins}m`;
    const days = Math.floor(hrs / 24);
    const remHrs = hrs % 24;
    return `${days}d ${remHrs}h`;
}

function updateRoomAge() {
    if (!state.roomCreatedAt) {
        chatRoomAge.textContent = "";
        return;
    }
    const now = Math.floor(Date.now() / 1000);
    const age = Math.max(0, now - state.roomCreatedAt);
    chatRoomAge.textContent = formatAge(age);
}

function startAgeTimer() {
    stopAgeTimer();
    updateRoomAge();
    state.ageTimer = setInterval(updateRoomAge, 1000);
}

function stopAgeTimer() {
    if (state.ageTimer) {
        clearInterval(state.ageTimer);
        state.ageTimer = null;
    }
    chatRoomAge.textContent = "";
}

// ─── Connection ─────────────────────────────────────────────────────────────

async function connectToServer(address) {
    if (state.connected) {
        showModal(
            i18n.t("modal.already_connected_title"),
            i18n.t("modal.already_connected_body", { address: state.serverAddress })
        );
        return;
    }

    // Ensure address has format host:port
    const host = address.trim();
    if (!host) return;

    // Show a connecting indicator in the modal
    showModal(
        i18n.t("modal.connecting_title"),
        i18n.t("modal.connecting_body", { host })
    );

    try {
        const handle = await window.__TAURI__.core.invoke("connect", { host });

        state.handle = handle;
        state.connected = true;
        state.serverAddress = host;

        updateConnectionStatus();
        hideModal();
        announce(i18n.t("lobby.connected_as", { handle }));

        // Switch to lobby view
        lobbyServerName.textContent = host;
        lobbyHandle.textContent = i18n.t("lobby.connected_as", { handle });
        showView("lobby");
    } catch (e) {
        const msg = String(e);
        showModal(i18n.t("modal.connection_failed"), msg);
        announceError(`${i18n.t("modal.connection_failed")}: ${msg}`);
    }
}

async function disconnectFromServer() {
    try {
        await window.__TAURI__.core.invoke("disconnect");
    } catch (_) {
        // Ignore errors on disconnect
    }

    resetState();
    showView("home");
    announce(i18n.t("chat.disconnected"));
}

function resetState() {
    state.handle = null;
    state.connected = false;
    state.currentRoom = null;
    state.currentRoomName = null;
    state.serverAddress = null;
    state.members = [];
    state.isCreator = false;
    state.roomCreatedAt = null;
    stopAgeTimer();

    updateConnectionStatus();
    updateRoomSection();
}

// ─── Rooms ──────────────────────────────────────────────────────────────────

async function createRoom() {
    const name = createRoomName.value.trim() || "unnamed";
    const hidden = createRoomHidden.checked;
    const password = createRoomPasswordToggle.checked ? createRoomPassword.value : null;

    if (createRoomPasswordToggle.checked && !createRoomPassword.value) {
        showModal(i18n.t("modal.error"), i18n.t("modal.password_required"));
        return;
    }

    try {
        await window.__TAURI__.core.invoke("create_room", {
            name,
            msgExpiry: null,
            hidden,
            password,
        });
        createRoomName.value = "";
        createRoomPassword.value = "";
        createRoomPasswordToggle.checked = false;
        createRoomPassword.disabled = true;
        createRoomHidden.checked = false;
    } catch (e) {
        showModal(i18n.t("modal.error"), String(e));
    }
}

async function joinRoom() {
    const roomId = joinRoomId.value.trim();
    if (!roomId) return;

    const password = joinRoomPassword.value || null;

    try {
        await window.__TAURI__.core.invoke("join_room", { roomId, password });
        joinRoomId.value = "";
        joinRoomPassword.value = "";
    } catch (e) {
        showModal(i18n.t("modal.error"), String(e));
    }
}

async function listRooms() {
    try {
        await window.__TAURI__.core.invoke("list_rooms");
    } catch (e) {
        // Silently fail — list stays as-is
    }
}

function renderRoomList(rooms) {
    lobbyRoomList.innerHTML = "";

    if (!rooms || rooms.length === 0) {
        const empty = document.createElement("div");
        empty.className = "room-list-empty";
        const span = document.createElement("span");
        span.textContent = i18n.t("lobby.no_public_rooms");
        empty.appendChild(span);
        lobbyRoomList.appendChild(empty);
        return;
    }

    rooms.forEach((room) => {
        const entry = document.createElement("div");
        entry.className = "room-entry";
        entry.dataset.roomId = room.room_id;
        entry.setAttribute("role", "listitem");

        const name = document.createElement("span");
        name.className = "room-entry-name";
        name.textContent = room.name || room.room_id;

        const meta = document.createElement("span");
        meta.className = "room-entry-meta";

        const members = document.createElement("span");
        members.className = "room-entry-members";
        members.textContent = i18n.t("lobby.online", { count: room.member_count });

        const joinLabel = document.createElement("span");
        joinLabel.className = "room-entry-join";
        joinLabel.textContent = i18n.t("lobby.join");

        meta.appendChild(members);
        meta.appendChild(joinLabel);
        entry.appendChild(name);
        entry.appendChild(meta);

        entry.addEventListener("click", () => {
            joinRoomId.value = room.room_id;
            joinRoom();
        });

        lobbyRoomList.appendChild(entry);
    });
}

async function leaveRoom() {
    if (!state.currentRoom) return;

    try {
        await window.__TAURI__.core.invoke("leave_room");

        state.currentRoom = null;
        state.currentRoomName = null;
        state.members = [];
        state.isCreator = false;
        state.roomCreatedAt = null;
        stopAgeTimer();
        messagesEl.innerHTML = "";

        updateRoomSection();
        showView("lobby");
    } catch (e) {
        showModal(i18n.t("modal.error"), String(e));
    }
}

async function closeRoom() {
    if (!state.currentRoom || !state.isCreator) return;

    // Confirmation modal with safe DOM construction
    showModalWithConfirm(
        i18n.t("modal.close_room_title"),
        i18n.t("modal.close_room_body"),
        i18n.t("modal.close_room_confirm"),
        async () => {
            hideModal();
            try {
                await window.__TAURI__.core.invoke("close_room");
                state.currentRoom = null;
                state.currentRoomName = null;
                state.members = [];
                state.isCreator = false;
                state.roomCreatedAt = null;
                stopAgeTimer();
                messagesEl.innerHTML = "";
                updateRoomSection();
                showView("lobby");
            } catch (e) {
                showModal(i18n.t("modal.error"), String(e));
            }
        }
    );
}

// ─── Chat ───────────────────────────────────────────────────────────────────

async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;
    if (!state.currentRoom) return;

    chatInput.value = "";

    try {
        await window.__TAURI__.core.invoke("send_message", { text });
        addMessage(state.handle || "you", text);
    } catch (e) {
        addErrorMessage(i18n.t("chat.send_failed", { error: e }));
    }
}

// ─── Modal ──────────────────────────────────────────────────────────────────

/** Element that had focus before the modal opened */
let previouslyFocused = null;

/** Trap Tab key inside the modal */
function trapFocus(e) {
    if (e.key !== "Tab") return;
    const modal = document.getElementById("modal");
    const focusable = modal.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (e.shiftKey) {
        if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
        }
    } else {
        if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }
}

/**
 * Show a modal with plain text content (safe — no innerHTML).
 */
function showModal(title, bodyText) {
    modalTitle.textContent = title;
    // Hide the DC form fields, show custom content
    const dcFields = modalBody.querySelectorAll(".form-group, .btn-primary");
    dcFields.forEach((el) => el.style.display = "none");
    // Create or update a generic content div
    let generic = modalBody.querySelector(".modal-generic");
    if (!generic) {
        generic = document.createElement("div");
        generic.className = "modal-generic";
        modalBody.appendChild(generic);
    }
    // Safe: use textContent, NOT innerHTML
    generic.textContent = "";
    const p = document.createElement("p");
    p.textContent = bodyText;
    generic.appendChild(p);
    generic.style.display = "block";
    previouslyFocused = document.activeElement;
    modalOverlay.classList.remove("hidden");
    document.addEventListener("keydown", trapFocus);
    // Focus the close button so screen readers land inside the modal
    setTimeout(() => modalClose.focus(), 50);
}

/**
 * Show a modal with a confirmation button (safe — no innerHTML).
 */
function showModalWithConfirm(title, bodyText, confirmLabel, onConfirm) {
    modalTitle.textContent = title;
    const dcFields = modalBody.querySelectorAll(".form-group, .btn-primary");
    dcFields.forEach((el) => el.style.display = "none");
    let generic = modalBody.querySelector(".modal-generic");
    if (!generic) {
        generic = document.createElement("div");
        generic.className = "modal-generic";
        modalBody.appendChild(generic);
    }
    generic.textContent = "";

    const p = document.createElement("p");
    p.textContent = bodyText;
    p.style.marginBottom = "16px";
    generic.appendChild(p);

    const btn = document.createElement("button");
    btn.className = "btn-danger";
    btn.style.width = "100%";
    btn.textContent = confirmLabel;
    btn.addEventListener("click", onConfirm);
    generic.appendChild(btn);

    generic.style.display = "block";
    previouslyFocused = document.activeElement;
    modalOverlay.classList.remove("hidden");
    document.addEventListener("keydown", trapFocus);
    setTimeout(() => modalClose.focus(), 50);
}

function showDirectConnectModal() {
    modalTitle.textContent = i18n.t("modal.direct_connect");
    // Show DC form fields, hide generic content
    const dcFields = modalBody.querySelectorAll(".form-group, .btn-primary");
    dcFields.forEach((el) => el.style.display = "");
    const generic = modalBody.querySelector(".modal-generic");
    if (generic) generic.style.display = "none";
    // Reset fields
    dcHost.value = "";
    dcPort.value = "";
    dcConnectBtn.disabled = false;
    dcConnectBtn.textContent = i18n.t("modal.connect");
    previouslyFocused = document.activeElement;
    modalOverlay.classList.remove("hidden");
    document.addEventListener("keydown", trapFocus);
    setTimeout(() => dcHost.focus(), 50);
}

function hideModal() {
    modalOverlay.classList.add("hidden");
    document.removeEventListener("keydown", trapFocus);
    // Restore focus to the element that opened the modal
    if (previouslyFocused && previouslyFocused.focus) {
        previouslyFocused.focus();
        previouslyFocused = null;
    }
}

// ─── Tauri Event Listeners ──────────────────────────────────────────────────

function setupEventListeners() {
    const listen = window.__TAURI__.event.listen;

    // Incoming chat message (decrypted by Rust backend)
    listen("retro://message", (event) => {
        const { from, text } = event.payload;
        addMessage(from, text);
    });

    // Incoming DM
    listen("retro://dm", (event) => {
        const { from, text } = event.payload;
        addDM(from, text, false);
    });

    // Member joined
    listen("retro://member-joined", (event) => {
        const { handle } = event.payload;
        state.members.push({ handle });
        updateMemberList();
        addSystemMessage(i18n.t("chat.member_joined", { handle }));
        announce(i18n.t("chat.member_joined", { handle }));
    });

    // Member left
    listen("retro://member-left", (event) => {
        const { handle } = event.payload;
        state.members = state.members.filter((m) => m.handle !== handle);
        updateMemberList();
        addSystemMessage(i18n.t("chat.member_left", { handle }));
    });

    // Room closed by creator
    listen("retro://room-closed", (event) => {
        addSystemMessage(i18n.t("chat.room_closed"));
        announce(i18n.t("chat.room_closed"));
        state.currentRoom = null;
        state.currentRoomName = null;
        state.members = [];
        state.isCreator = false;
        state.roomCreatedAt = null;
        stopAgeTimer();
        updateRoomSection();

        if (state.connected) {
            showView("lobby");
        }
    });

    // Room list
    listen("retro://room-list", (event) => {
        const { rooms } = event.payload;
        renderRoomList(rooms);
    });

    // Server error
    listen("retro://error", (event) => {
        const { message } = event.payload;
        if (state.currentView === "chat") {
            addErrorMessage(`${i18n.t("modal.server_error")}: ${message}`);
        } else {
            showModal(i18n.t("modal.server_error"), message);
            announceError(`${i18n.t("modal.server_error")}: ${message}`);
        }
    });

    // Disconnected
    listen("retro://disconnected", (_event) => {
        const wasInChat = state.currentView === "chat";
        resetState();

        if (wasInChat) {
            addSystemMessage(i18n.t("chat.disconnected"));
        }

        announce(i18n.t("chat.disconnected"));
        showView("home");
    });

    // Room joined
    listen("retro://room-joined", (event) => {
        const { room_id, members, config, is_creator, created_at } = event.payload;
        state.currentRoom = room_id;
        state.currentRoomName = config?.name || room_id.substring(0, 16);
        state.members = members.map((m) => ({ handle: m.handle || m }));
        state.isCreator = is_creator || false;
        state.roomCreatedAt = created_at || null;

        if (!state.members.find((m) => m.handle === state.handle)) {
            state.members.push({ handle: state.handle });
        }

        // Switch to chat view
        chatRoomName.textContent = state.currentRoomName;
        messagesEl.innerHTML = "";
        addSystemMessage(i18n.t("chat.joined", { name: state.currentRoomName }));
        announce(i18n.t("chat.joined", { name: state.currentRoomName }));
        updateCloseButton();
        startAgeTimer();

        updateRoomSection();
        showView("chat");
        chatInput.focus();
    });

    // Room created
    listen("retro://room-created", (event) => {
        const { room_id, is_creator, created_at } = event.payload;
        state.currentRoom = room_id;
        state.currentRoomName = createRoomName.value || room_id.substring(0, 16);
        state.members = [{ handle: state.handle }];
        state.isCreator = is_creator || true;
        state.roomCreatedAt = created_at || null;

        chatRoomName.textContent = state.currentRoomName;
        messagesEl.innerHTML = "";
        addSystemMessage(i18n.t("chat.room_created"));
        addSystemMessage(room_id);
        updateCloseButton();
        startAgeTimer();

        updateRoomSection();
        showView("chat");
        chatInput.focus();
    });

    // System message from backend
    listen("retro://system", (event) => {
        const { message } = event.payload;
        if (state.currentView === "chat") {
            addSystemMessage(message);
        }
    });
}

// ─── Click Handlers ─────────────────────────────────────────────────────────

// Sidebar navigation
sidebarNav.querySelectorAll(".nav-btn[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        if (view) showView(view);
    });
});

// Direct Connect button opens modal
btnDirectConnect.addEventListener("click", showDirectConnectModal);

// Session button — return to lobby or chat
btnSession.addEventListener("click", () => {
    if (state.currentRoom) {
        showView("chat");
    } else if (state.connected) {
        showView("lobby");
    }
});

// Clicking room info in sidebar returns to chat
roomInfoEl.addEventListener("click", () => {
    if (state.currentRoom) showView("chat");
});

// Settings button
settingsBtn.addEventListener("click", () => showView("settings"));

// Theme toggle
themeToggles.forEach((btn) => {
    btn.addEventListener("click", () => setTheme(btn.dataset.theme));
});

// Font size toggle
fontSizeToggles.forEach((btn) => {
    btn.addEventListener("click", () => setFontSize(btn.dataset.fontsize));
});

// Reduced motion toggle
reducedMotionToggle.addEventListener("change", () => {
    setReducedMotion(reducedMotionToggle.checked);
});

// High contrast toggle
highContrastToggle.addEventListener("change", () => {
    setHighContrast(highContrastToggle.checked);
});

// Language select
languageSelect.addEventListener("change", async () => {
    await i18n.setLocale(languageSelect.value);
    // Re-apply dynamic text that data-i18n can't cover
    updateConnectionStatus();
    updateSessionButton();
    if (state.currentRoom) {
        updateMemberList();
    }
});

// Direct connect (inside modal)
dcConnectBtn.addEventListener("click", () => {
    const host = dcHost.value.trim();
    const port = dcPort.value.trim();
    if (!host) { dcHost.focus(); return; }
    const address = port ? `${host}:${port}` : host;
    connectToServer(address);
});

// Enter key on direct connect fields
dcHost.addEventListener("keydown", (e) => {
    if (e.key === "Enter") dcConnectBtn.click();
});
dcPort.addEventListener("keydown", (e) => {
    if (e.key === "Enter") dcConnectBtn.click();
});

// Lobby: Create room
btnCreateRoom.addEventListener("click", createRoom);
createRoomName.addEventListener("keydown", (e) => {
    if (e.key === "Enter") createRoom();
});

// Lobby: Password toggle enables/disables password input
createRoomPasswordToggle.addEventListener("change", () => {
    createRoomPassword.disabled = !createRoomPasswordToggle.checked;
    if (createRoomPasswordToggle.checked) {
        createRoomPassword.focus();
    } else {
        createRoomPassword.value = "";
    }
});

// Lobby: Join room
btnJoinRoom.addEventListener("click", joinRoom);
joinRoomId.addEventListener("keydown", (e) => {
    if (e.key === "Enter") joinRoom();
});

// Lobby: Disconnect
btnDisconnect.addEventListener("click", disconnectFromServer);

// Lobby: Refresh rooms
btnRefreshRooms.addEventListener("click", listRooms);

// Chat: Send message
btnSend.addEventListener("click", sendMessage);
chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
});

// Chat: Leave room
btnLeaveRoom.addEventListener("click", leaveRoom);

// Chat: Close room (creator only)
btnCloseRoom.addEventListener("click", closeRoom);

// Modal close
modalClose.addEventListener("click", hideModal);
modalOverlay.addEventListener("click", (e) => {
    if (e.target === modalOverlay) hideModal();
});

// Escape key closes modal
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !modalOverlay.classList.contains("hidden")) {
        hideModal();
    }
});

// ─── Window Controls ────────────────────────────────────────────────────────

document.getElementById("btn-close").addEventListener("click", async () => {
    await window.__TAURI__.core.invoke("window_close");
});

document.getElementById("btn-minimize").addEventListener("click", async () => {
    await window.__TAURI__.core.invoke("window_minimize");
});

document.getElementById("btn-maximize").addEventListener("click", async () => {
    await window.__TAURI__.core.invoke("window_maximize_toggle");
});

// ─── Window Dragging ───────────────────────────────────────────────────────

// Allow dragging the window from the drag region and sidebar brand
document.getElementById("drag-region").addEventListener("mousedown", async () => {
    await window.__TAURI__.core.invoke("window_start_drag");
});

document.getElementById("sidebar-brand").addEventListener("mousedown", async (e) => {
    // Don't drag if clicking a window control button
    if (e.target.closest(".window-controls")) return;
    await window.__TAURI__.core.invoke("window_start_drag");
});

// ─── Initialize ─────────────────────────────────────────────────────────────

async function init() {
    loadTheme();
    loadFontSize();
    loadReducedMotion();
    loadHighContrast();

    // Initialize i18n — loads locale JSON then applies translations
    await i18n.init();
    populateLanguageSelect();

    setupEventListeners();
    updateConnectionStatus();
    showView("home");
}

init();
