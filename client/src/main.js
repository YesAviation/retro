/**
 * Retro — UI Application
 *
 * Proper GUI with sidebar navigation, server browsers, direct connect,
 * Matrix-style chat view, and settings panel.
 *
 * No keyboard commands. Everything is mouse-driven.
 * Communicates with the Tauri Rust backend via IPC.
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
    official: document.getElementById("view-official"),
    servers: document.getElementById("view-servers"),
    chat: document.getElementById("view-chat"),
    lobby: document.getElementById("view-lobby"),
    settings: document.getElementById("view-settings"),
};

// Server lists
const officialListEl = document.getElementById("official-list");
const serversListEl = document.getElementById("servers-list");

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

// ─── State ──────────────────────────────────────────────────────────────────

const state = {
    handle: null,
    currentRoom: null,
    currentRoomName: null,
    connected: false,
    serverAddress: null,
    members: [],
    currentView: "official",
    isCreator: false,
    roomCreatedAt: null,
    ageTimer: null,
};

// ─── View Management ────────────────────────────────────────────────────────

function showView(viewName) {
    // Hide all views
    Object.values(views).forEach((v) => v.classList.remove("active"));

    // Show target view
    const target = views[viewName];
    if (target) {
        target.classList.add("active");
    }

    // Update nav button active state (only for nav buttons, not settings)
    sidebarNav.querySelectorAll(".nav-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.view === viewName);
    });

    // Settings button active state
    settingsBtn.classList.toggle("active", viewName === "settings");

    // Session button active state
    btnSession.classList.toggle("active", viewName === "lobby" || viewName === "chat");

    state.currentView = viewName;

    // Auto-fetch server lists when switching to those views
    if (viewName === "official") fetchOfficialServers();
    if (viewName === "servers") fetchServerList();
    if (viewName === "lobby") listRooms();
}

// ─── Theme ──────────────────────────────────────────────────────────────────

function setTheme(theme) {
    const root = document.documentElement;
    root.classList.remove("theme-dark", "theme-light");
    root.classList.add(`theme-${theme}`);

    // Update toggle buttons
    themeToggles.forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.theme === theme);
    });

    localStorage.setItem("retro-theme", theme);
}

function loadTheme() {
    const saved = localStorage.getItem("retro-theme");
    setTheme(saved || "dark");
}

// ─── Connection Status ──────────────────────────────────────────────────────

function updateConnectionStatus() {
    if (state.connected) {
        statusDot.className = "dot-connected";
        statusText.textContent = state.serverAddress || "Connected";
    } else {
        statusDot.className = "dot-disconnected";
        statusText.textContent = "Not connected";
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
        btnSessionLabel.textContent = "Chat Room";
    } else {
        btnSessionLabel.textContent = "Lobby";
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
            youSpan.textContent = " (you)";
            li.appendChild(youSpan);
        }

        memberListEl.appendChild(li);
    });
}

// ─── Chat Messages ──────────────────────────────────────────────────────────

function addMessage(handle, text) {
    const div = document.createElement("div");
    div.className = "msg";

    const h = document.createElement("span");
    h.className = "msg-handle";
    h.textContent = `${handle} `;

    const t = document.createElement("span");
    t.className = "msg-text";
    t.textContent = text;

    div.appendChild(h);
    div.appendChild(t);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addDM(from, text, outgoing) {
    const div = document.createElement("div");
    div.className = "msg msg-dm";

    const label = document.createElement("span");
    label.className = "msg-label";
    label.textContent = outgoing ? `DM to ${from}: ` : `DM from ${from}: `;

    const t = document.createElement("span");
    t.textContent = text;

    div.appendChild(label);
    div.appendChild(t);
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addSystemMessage(text) {
    const div = document.createElement("div");
    div.className = "msg msg-system";
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addErrorMessage(text) {
    const div = document.createElement("div");
    div.className = "msg msg-error";
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
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
    chatRoomAge.textContent = `⏱ ${formatAge(age)}`;
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

// ─── Server List Rendering ──────────────────────────────────────────────────

function renderServerList(container, servers, emptyIcon, emptyText, emptyHint) {
    container.innerHTML = "";

    if (!servers || servers.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">${emptyIcon}</div>
                <p>${emptyText}</p>
                <p class="empty-hint">${emptyHint}</p>
            </div>
        `;
        return;
    }

    servers.forEach((s) => {
        const card = document.createElement("div");
        card.className = "server-card";
        card.addEventListener("click", () => connectToServer(s.address));

        const info = document.createElement("div");
        info.className = "server-card-info";

        const name = document.createElement("div");
        name.className = "server-card-name";
        name.textContent = (s.official ? "★ " : "") + s.name;
        info.appendChild(name);

        if (s.description) {
            const desc = document.createElement("div");
            desc.className = "server-card-desc";
            desc.textContent = s.description;
            info.appendChild(desc);
        }

        const meta = document.createElement("div");
        meta.className = "server-card-meta";

        const players = document.createElement("span");
        players.className = "server-card-players";
        const maxP = s.max_players > 0 ? `/${s.max_players}` : "";
        players.textContent = `${s.player_count}${maxP} players`;
        meta.appendChild(players);

        const addr = document.createElement("span");
        addr.className = "server-card-address";
        addr.textContent = s.address;
        meta.appendChild(addr);

        card.appendChild(info);
        card.appendChild(meta);
        container.appendChild(card);
    });
}

// ─── Server Discovery ───────────────────────────────────────────────────────

async function fetchOfficialServers() {
    try {
        const servers = await window.__TAURI__.core.invoke("fetch_servers", {
            registryUrl: null,
            officialOnly: true,
        });
        renderServerList(
            officialListEl,
            servers,
            "★",
            "No official servers available",
            "Check back later or use Direct Connect"
        );
    } catch (e) {
        renderServerList(
            officialListEl,
            [],
            "★",
            "Could not reach registry",
            String(e)
        );
    }
}

async function fetchServerList() {
    try {
        const servers = await window.__TAURI__.core.invoke("fetch_servers", {
            registryUrl: null,
            officialOnly: false,
        });
        renderServerList(
            serversListEl,
            servers,
            "◆",
            "No servers found",
            "No self-hosted servers are broadcasting right now"
        );
    } catch (e) {
        renderServerList(
            serversListEl,
            [],
            "◆",
            "Could not reach registry",
            String(e)
        );
    }
}

// ─── Connection ─────────────────────────────────────────────────────────────

async function connectToServer(address) {
    if (state.connected) {
        showModal("Already Connected", `<p>You're already connected to ${state.serverAddress}. Disconnect first.</p>`);
        return;
    }

    // Ensure address has format host:port
    const host = address.trim();
    if (!host) return;

    // Show a connecting indicator in the modal
    showModal("Connecting", `<p>Establishing secure connection to ${host}...</p><p class="chat-meta">Generating RSA-4096 keys...</p>`);
    console.log("[retro] connecting to", host);

    try {
        const handle = await window.__TAURI__.core.invoke("connect", { host });
        console.log("[retro] connected as", handle);

        state.handle = handle;
        state.connected = true;
        state.serverAddress = host;

        updateConnectionStatus();
        hideModal();

        // Switch to lobby view
        lobbyServerName.textContent = host;
        lobbyHandle.textContent = `Connected as ${handle}`;
        showView("lobby");
    } catch (e) {
        console.error("[retro] connection failed:", e);
        showModal("Connection Failed", `<p>${e}</p>`);
    }
}

async function disconnectFromServer() {
    try {
        await window.__TAURI__.core.invoke("disconnect");
    } catch (_) {
        // Ignore errors on disconnect
    }

    resetState();
    showView("official");
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
        showModal("Error", "<p>Enter a password or disable the password option.</p>");
        return;
    }

    try {
        await window.__TAURI__.core.invoke("create_room", {
            name,
            msgExpiry: null,
            fileExpiry: null,
            hidden,
            password,
        });
        createRoomName.value = "";
        createRoomPassword.value = "";
        createRoomPasswordToggle.checked = false;
        createRoomPassword.disabled = true;
        createRoomHidden.checked = false;
        // Room creation handled via retro://room-created event
    } catch (e) {
        showModal("Error", `<p>${e}</p>`);
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
        // Room join handled via retro://room-joined event
    } catch (e) {
        showModal("Error", `<p>${e}</p>`);
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
        lobbyRoomList.innerHTML = `<div class="room-list-empty"><span>No public rooms</span></div>`;
        return;
    }

    rooms.forEach((room) => {
        const entry = document.createElement("div");
        entry.className = "room-entry";
        entry.dataset.roomId = room.room_id;

        const name = document.createElement("span");
        name.className = "room-entry-name";
        name.textContent = room.name || room.room_id;

        const meta = document.createElement("span");
        meta.className = "room-entry-meta";

        const members = document.createElement("span");
        members.className = "room-entry-members";
        members.textContent = `${room.member_count} online`;

        const joinLabel = document.createElement("span");
        joinLabel.className = "room-entry-join";
        joinLabel.textContent = "Join →";

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
        showModal("Error", `<p>${e}</p>`);
    }
}

async function closeRoom() {
    if (!state.currentRoom || !state.isCreator) return;

    // Confirmation modal
    showModal("Close Room?", `
        <p style="margin-bottom:12px">This will <strong>permanently destroy</strong> all messages, files, and encryption keys for this room.</p>
        <p style="margin-bottom:16px; color:var(--danger)">This action cannot be undone.</p>
        <button id="confirm-close-room" class="btn-danger" style="width:100%">Destroy Room</button>
    `);

    // Wait for confirm button (it's dynamically added to modal)
    setTimeout(() => {
        const confirmBtn = document.getElementById("confirm-close-room");
        if (confirmBtn) {
            confirmBtn.addEventListener("click", async () => {
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
                    showModal("Error", `<p>${e}</p>`);
                }
            });
        }
    }, 0);
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
        addErrorMessage(`Failed to send: ${e}`);
    }
}

// ─── Modal ──────────────────────────────────────────────────────────────────

function showModal(title, bodyHtml) {
    // For generic modals, temporarily replace the body
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
    generic.innerHTML = bodyHtml;
    generic.style.display = "block";
    modalOverlay.classList.remove("hidden");
}

function showDirectConnectModal() {
    modalTitle.textContent = "Direct Connect";
    // Show DC form fields, hide generic content
    const dcFields = modalBody.querySelectorAll(".form-group, .btn-primary");
    dcFields.forEach((el) => el.style.display = "");
    const generic = modalBody.querySelector(".modal-generic");
    if (generic) generic.style.display = "none";
    // Reset fields
    dcHost.value = "";
    dcPort.value = "";
    dcConnectBtn.disabled = false;
    dcConnectBtn.textContent = "Connect";
    modalOverlay.classList.remove("hidden");
    setTimeout(() => dcHost.focus(), 50);
}

function hideModal() {
    modalOverlay.classList.add("hidden");
}

// ─── Tauri Event Listeners ──────────────────────────────────────────────────

function setupEventListeners() {
    const listen = window.__TAURI__.event.listen;
    console.log("[retro] Setting up event listeners...");

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
        addSystemMessage(`${handle} joined the room`);
    });

    // Member left
    listen("retro://member-left", (event) => {
        const { handle } = event.payload;
        state.members = state.members.filter((m) => m.handle !== handle);
        updateMemberList();
        addSystemMessage(`${handle} left the room`);
    });

    // Room closed by creator
    listen("retro://room-closed", (event) => {
        addSystemMessage("Room closed by creator. All data destroyed.");
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

    // File available
    listen("retro://file-available", (event) => {
        const { file_id, from, size } = event.payload;
        const sizeKB = Math.round(size / 1024);
        addSystemMessage(`File available from ${from}: ${file_id} (${sizeKB} KB)`);
    });

    // Server error
    listen("retro://error", (event) => {
        const { message } = event.payload;
        if (state.currentView === "chat") {
            addErrorMessage(`Server: ${message}`);
        } else {
            showModal("Server Error", `<p>${message}</p>`);
        }
    });

    // Disconnected
    listen("retro://disconnected", (_event) => {
        const wasInChat = state.currentView === "chat";
        resetState();

        if (wasInChat) {
            addSystemMessage("Disconnected from server.");
        }

        showView("official");
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
        addSystemMessage(`Joined room — ${state.currentRoomName}`);
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
        addSystemMessage(`Room created — share this ID to invite others:`);
        addSystemMessage(room_id);
        updateCloseButton();
        startAgeTimer();

        updateRoomSection();
        showView("chat");
        chatInput.focus();
    });

    // File downloaded
    listen("retro://file-downloaded", (event) => {
        const { file_id, path, size } = event.payload;
        const sizeKB = Math.round(size / 1024);
        addSystemMessage(`File ${file_id} saved to ${path} (${sizeKB} KB)`);
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

// Sidebar navigation (only view-switching buttons)
sidebarNav.querySelectorAll(".nav-btn[data-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        if (view) showView(view);
    });
});

// Direct Connect button opens modal instead of switching view
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

// ─── Initialize ─────────────────────────────────────────────────────────────

console.log("[retro] Initializing...", window.__TAURI__ ? "Tauri API available" : "NO TAURI API");
loadTheme();
setupEventListeners();
updateConnectionStatus();
showView("official");
console.log("[retro] Ready.");
