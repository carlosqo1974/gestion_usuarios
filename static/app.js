"use strict";

// ─── Estado global ────────────────────────────────────────────────────────
const state = {
  currentUser: null,    // objeto usuario activo
  hoursMatrix: null,    // copia editable de la matriz de horarios
  isDragging: false,
  dragValue: null,
};

const currentUser = window.APP_USER || {};
const perms = currentUser.permissions || {};

// ─── Bootstrap modals ────────────────────────────────────────────────────
const pwdModal   = new bootstrap.Modal(document.getElementById("pwdModal"));
const hoursModal = new bootstrap.Modal(document.getElementById("hoursModal"));
const appToast   = new bootstrap.Toast(document.getElementById("app-toast"), { delay: 4000 });

// ─── Toast helper ─────────────────────────────────────────────────────────
function toast(msg, type = "success") {
  const el = document.getElementById("app-toast");
  el.className = `toast align-items-center text-bg-${type} border-0`;
  document.getElementById("toast-msg").textContent = msg;
  appToast.show();
}

// ─── Fetch helper ─────────────────────────────────────────────────────────
async function api(url, opts = {}) {
  const res  = await fetch(url, opts);
  const data = await res.json();
  return data;
}

// ─── Verificar conexión ───────────────────────────────────────────────────
async function checkConnection() {
  const badge = document.getElementById("conn-badge");
  badge.innerHTML = `<i class="bi bi-circle-fill me-1"></i>Verificando…`;
  badge.className = "badge bg-secondary";

  const data = await api("/api/status");
  if (data.connected) {
    badge.innerHTML = `<i class="bi bi-circle-fill me-1"></i>Conectado`;
    badge.className = "badge bg-success";
    loadTree();
  } else {
    badge.innerHTML = `<i class="bi bi-circle-fill me-1"></i>Sin conexión`;
    badge.className = "badge bg-danger";
    badge.title = data.message;
    toast(`Error de conexión: ${data.message}`, "danger");
  }
}

// ─── Árbol de OUs ─────────────────────────────────────────────────────────
async function loadTree() {
  const container = document.getElementById("ou-tree");
  container.innerHTML = `<div class="text-muted text-center py-2"><div class="spinner-border spinner-border-sm"></div></div>`;

  const data = await api("/api/tree");
  if (!data.ok) {
    container.innerHTML = `<div class="text-danger small p-2">${data.error}</div>`;
    return;
  }

  container.innerHTML = "";
  data.nodes.forEach(node => {
    const depth = (node.dn.split(",").length - 1);
    const div = document.createElement("div");
    div.className = "ou-item";
    div.style.paddingLeft = `${Math.min(depth * 10, 40)}px`;
    div.title = node.dn;
    div.innerHTML = `<i class="bi bi-folder2 me-1 text-warning"></i>${escHtml(node.name)}`;
    div.addEventListener("click", () => {
      document.querySelectorAll(".ou-item").forEach(el => el.classList.remove("active"));
      div.classList.add("active");
    });
    container.appendChild(div);
  });
}

// ─── Búsqueda de usuarios ─────────────────────────────────────────────────
document.getElementById("search-btn").addEventListener("click", searchUsers);
document.getElementById("search-input").addEventListener("keydown", e => {
  if (e.key === "Enter") searchUsers();
});

async function searchUsers() {
  const term = document.getElementById("search-input").value.trim();
  if (!term) return;

  const listEl = document.getElementById("user-list");
  listEl.innerHTML = `<div class="text-center py-4"><div class="spinner-border text-primary"></div></div>`;

  const url = `/api/search?q=${encodeURIComponent(term)}`;
  const data  = await api(url);

  if (!data.ok) {
    listEl.innerHTML = `<div class="text-danger small p-3">${data.error}</div>`;
    return;
  }

  if (data.users.length === 0) {
    listEl.innerHTML = `<div class="text-muted small text-center p-3">Sin resultados</div>`;
    return;
  }

  listEl.innerHTML = `<div class="px-3 py-1 text-muted" style="font-size:.75rem">${data.count} resultado(s)</div>`;
  data.users.forEach(u => {
    const item = document.createElement("div");
    item.className = "user-item";
    item.dataset.sam = u.sAMAccountName;
    const enabled = u.enabled;
    item.innerHTML = `
      <div class="d-flex align-items-center">
        <span class="badge-status ${enabled ? "badge-enabled" : "badge-disabled"}"></span>
        <div class="overflow-hidden">
          <div class="fw-semibold text-truncate">${escHtml(u.displayName || u.cn || u.sAMAccountName)}</div>
          <div class="text-muted" style="font-size:.75rem">${escHtml(u.sAMAccountName)}</div>
        </div>
      </div>`;
    item.addEventListener("click", () => selectUser(u.sAMAccountName, item));
    listEl.appendChild(item);
  });
}

async function selectUser(sam, itemEl) {
  document.querySelectorAll(".user-item").forEach(el => el.classList.remove("active"));
  if (itemEl) itemEl.classList.add("active");

  showDetailLoading();
  const data = await api(`/api/user/${encodeURIComponent(sam)}`);
  if (!data.ok) {
    toast(`Error: ${data.error}`, "danger");
    return;
  }
  state.currentUser = data.user;
  renderDetail(data.user);
}

// ─── Panel de detalle ────────────────────────────────────────────────────
function showDetailLoading() {
  document.getElementById("detail-panel").innerHTML = `
    <div class="d-flex justify-content-center align-items-center h-100">
      <div class="spinner-border text-primary"></div>
    </div>`;
}

function renderDetail(u) {
  const enabled  = u.enabled;
  const locked   = u.lockoutTime && u.lockoutTime !== "Nunca";
  const initials = getInitials(u.displayName || u.cn || u.sAMAccountName);

  const html = `
    <!-- Cabecera -->
    <div class="user-header">
      <div class="user-avatar">${escHtml(initials)}</div>
      <div>
        <h4 class="mb-0">${escHtml(u.displayName || u.cn || u.sAMAccountName)}</h4>
        <div class="text-muted">${escHtml(u.sAMAccountName)}${u.mail ? " · " + escHtml(u.mail) : ""}</div>
        ${u.title     ? `<small class="text-muted">${escHtml(u.title)}</small>` : ""}
        ${u.department? `<small class="text-muted ms-2">· ${escHtml(u.department)}</small>` : ""}
      </div>
    </div>

    <!-- Badges de estado -->
    <div class="status-row">
      <span class="badge ${enabled ? "bg-success" : "bg-danger"}">
        <i class="bi bi-${enabled ? "check-circle" : "x-circle"} me-1"></i>
        ${enabled ? "Cuenta activa" : "Cuenta deshabilitada"}
      </span>
      ${locked ? `<span class="badge bg-warning text-dark"><i class="bi bi-lock-fill me-1"></i>Bloqueada</span>` : ""}
      ${u.password_never_expires ? `<span class="badge bg-info text-dark"><i class="bi bi-infinity me-1"></i>Contraseña no expira</span>` : ""}
      ${u.logon_hours_unrestricted ? `<span class="badge bg-secondary"><i class="bi bi-clock me-1"></i>Acceso 24/7</span>` : `<span class="badge bg-primary"><i class="bi bi-clock me-1"></i>Horario restringido</span>`}
    </div>

    <!-- Acciones -->
    <div class="d-flex flex-wrap gap-2 mb-4">
      ${perms.can_change_password ? `<button class="btn btn-sm btn-outline-danger" id="btn-pwd">
        <i class="bi bi-key me-1"></i>Cambiar contraseña
      </button>` : ""}
      ${perms.can_change_hours ? `<button class="btn btn-sm btn-outline-primary" id="btn-hours">
        <i class="bi bi-clock me-1"></i>Editar horarios
      </button>` : ""}
      ${perms.can_reset_account ? `<button class="btn btn-sm ${enabled ? "btn-outline-warning" : "btn-outline-success"}" id="btn-toggle">
        <i class="bi bi-${enabled ? "pause-circle" : "play-circle"} me-1"></i>
        ${enabled ? "Deshabilitar" : "Habilitar"}
      </button>` : ""}
      ${(perms.can_reset_account && locked) ? `<button class="btn btn-sm btn-outline-secondary" id="btn-unlock">
        <i class="bi bi-unlock me-1"></i>Desbloquear
      </button>` : ""}
    </div>

    <!-- Info general -->
    <div class="section-heading">Información general</div>
    <div class="info-grid mb-4">
      ${infoCard("Cuenta", u.sAMAccountName)}
      ${infoCard("Nombre completo", u.displayName || u.cn)}
      ${infoCard("Correo", u.mail)}
      ${infoCard("Departamento", u.department)}
      ${infoCard("Cargo", u.title)}
      ${infoCard("Teléfono", u.telephoneNumber)}
      ${infoCard("Descripción", u.description)}
    </div>

    <!-- Info de inicio de sesión -->
    <div class="section-heading">Inicio de sesión</div>
    <div class="info-grid mb-4">
      ${infoCard("Último acceso", u.lastLogonTimestamp || u.lastLogon)}
      ${infoCard("Contraseña cambiada", u.pwdLastSet)}
      ${infoCard("Intentos fallidos", u.badPwdCount)}
      ${infoCard("Última contraseña fallida", u.badPasswordTime)}
      ${infoCard("Hora de bloqueo", u.lockoutTime)}
      ${infoCard("Creado", u.whenCreated)}
      ${infoCard("Modificado", u.whenChanged)}
    </div>

    <!-- Horario visual (solo lectura) -->
    <div class="section-heading">Horario de acceso permitido</div>
    <div id="inline-hours-wrap" class="mb-4 table-responsive"></div>

    <!-- DN y grupos -->
    <div class="section-heading">Directorio</div>
    <div class="info-grid mb-4">
      ${infoCard("DN", u.distinguishedName)}
    </div>
    ${u.memberOf && u.memberOf.length ? `
      <div class="section-heading">Grupos (${u.memberOf.length})</div>
      <div class="mb-4">
        ${u.memberOf.map(g => `<span class="badge bg-light text-dark border me-1 mb-1">${escHtml(shortDN(g))}</span>`).join("")}
      </div>` : ""}
  `;

  const panel = document.getElementById("detail-panel");
  panel.innerHTML = html;

  // Dibujar grid inline (solo lectura)
  buildHoursGrid("inline-hours-wrap", u.logon_hours_matrix, true);

  // Eventos de botones
  const btnPwd = document.getElementById("btn-pwd");
  const btnHours = document.getElementById("btn-hours");
  const btnToggle = document.getElementById("btn-toggle");
  const btnUnlock = document.getElementById("btn-unlock");

  if (btnPwd) btnPwd.addEventListener("click", () => openPwdModal(u));
  if (btnHours) btnHours.addEventListener("click", () => openHoursModal(u));
  if (btnToggle) btnToggle.addEventListener("click", () => toggleUser(u));
  if (btnUnlock) btnUnlock.addEventListener("click", () => unlockUser(u));
}

// ─── Helpers ──────────────────────────────────────────────────────────────
function infoCard(label, value) {
  if (!value && value !== 0) return "";
  return `<div class="info-card">
    <div class="label">${escHtml(label)}</div>
    <div class="value">${escHtml(String(value))}</div>
  </div>`;
}

function getInitials(name) {
  if (!name) return "?";
  return name.split(" ").slice(0, 2).map(w => w[0]).join("").toUpperCase();
}

function shortDN(dn) {
  return dn.split(",")[0].replace(/^CN=/i, "");
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Grid de horarios ─────────────────────────────────────────────────────
const DAYS  = ["Dom", "Lun", "Mar", "Mié", "Jue", "Vie", "Sáb"];
const HOURS = Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2,"0")}`);

function buildHoursGrid(containerId, matrix, readOnly = false) {
  const wrap  = document.getElementById(containerId);
  const table = document.createElement("table");
  table.className = "table table-bordered table-sm hours-grid mb-0";

  // Header con horas
  const thead = table.createTHead();
  const hrRow = thead.insertRow();
  const thDay = document.createElement("th");
  thDay.className = "day-header";
  hrRow.appendChild(thDay);
  HOURS.forEach(h => {
    const th = document.createElement("th");
    th.className = "hour-header";
    th.textContent = h;
    hrRow.appendChild(th);
  });

  // Filas de días
  const tbody = table.createTBody();
  matrix.forEach((dayHours, dayIdx) => {
    const row = tbody.insertRow();
    const thD = document.createElement("th");
    thD.className = "day-header";
    thD.textContent = DAYS[dayIdx];
    row.appendChild(thD);

    dayHours.forEach((allowed, hourIdx) => {
      const td = row.insertCell();
      td.className = allowed ? "allowed" : "denied";
      td.dataset.day  = dayIdx;
      td.dataset.hour = hourIdx;

      if (!readOnly) {
        td.addEventListener("mousedown", e => {
          e.preventDefault();
          state.isDragging = true;
          state.dragValue  = !allowed;
          toggleCell(td);
        });
        td.addEventListener("mouseenter", () => {
          if (state.isDragging) toggleCell(td);
        });
      }
    });
  });

  document.addEventListener("mouseup", () => { state.isDragging = false; });
  wrap.innerHTML = "";
  wrap.appendChild(table);
}

function toggleCell(td) {
  const day  = parseInt(td.dataset.day);
  const hour = parseInt(td.dataset.hour);
  state.hoursMatrix[day][hour] = state.dragValue;
  td.className = state.dragValue ? "allowed" : "denied";
}

// ─── Modal: Cambiar contraseña ─────────────────────────────────────────────
function openPwdModal(u) {
  if (!perms.can_change_password) {
    toast("No autorizado para cambiar contraseñas", "danger");
    return;
  }
  document.getElementById("pwd-user-name").textContent =
    `Usuario: ${u.displayName || u.sAMAccountName} (${u.sAMAccountName})`;
  document.getElementById("pwd-new").value        = "";
  document.getElementById("pwd-confirm").value    = "";
  document.getElementById("pwd-must-change").checked = true;
  document.getElementById("pwd-alert").className  = "alert d-none";
  pwdModal.show();
}

document.getElementById("pwd-toggle").addEventListener("click", () => {
  const inp = document.getElementById("pwd-new");
  const ico = document.querySelector("#pwd-toggle i");
  if (inp.type === "password") {
    inp.type = "text";
    ico.className = "bi bi-eye-slash";
  } else {
    inp.type = "password";
    ico.className = "bi bi-eye";
  }
});

document.getElementById("pwd-save-btn").addEventListener("click", async () => {
  const alertEl  = document.getElementById("pwd-alert");
  const newPwd   = document.getElementById("pwd-new").value;
  const confirm  = document.getElementById("pwd-confirm").value;

  if (newPwd.length < 7) {
    showAlert(alertEl, "danger", "La contraseña debe tener al menos 7 caracteres.");
    return;
  }
  if (newPwd !== confirm) {
    showAlert(alertEl, "danger", "Las contraseñas no coinciden.");
    return;
  }

  const btn = document.getElementById("pwd-save-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Cambiando…`;

  const mustChange = document.getElementById("pwd-must-change").checked;
  const data = await api("/api/user/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      dn: state.currentUser.distinguishedName,
      password: newPwd,
      must_change: mustChange,
    }),
  });

  btn.disabled = false;
  btn.innerHTML = `<i class="bi bi-shield-lock me-1"></i>Cambiar contraseña`;

  if (data.ok) {
    pwdModal.hide();
    toast(data.message, "success");
  } else {
    showAlert(alertEl, "danger", data.error || data.message);
  }
});

// ─── Modal: Horarios ───────────────────────────────────────────────────────
function openHoursModal(u) {
  if (!perms.can_change_hours) {
    toast("No autorizado para cambiar horarios", "danger");
    return;
  }
  document.getElementById("hours-user-name").textContent =
    `Usuario: ${u.displayName || u.sAMAccountName} (${u.sAMAccountName})`;

  // Clonar la matriz para edición
  state.hoursMatrix = u.logon_hours_matrix.map(d => [...d]);

  const unrestrictedChk = document.getElementById("hours-unrestricted-chk");
  unrestrictedChk.checked = u.logon_hours_unrestricted;
  toggleGridVisibility(!u.logon_hours_unrestricted);

  buildHoursGrid("hours-grid-wrap", state.hoursMatrix, false);
  hoursModal.show();
}

document.getElementById("hours-unrestricted-chk").addEventListener("change", function () {
  toggleGridVisibility(!this.checked);
});

function toggleGridVisibility(show) {
  document.getElementById("hours-grid-wrap").style.opacity = show ? "1" : ".3";
  document.getElementById("hours-grid-wrap").style.pointerEvents = show ? "auto" : "none";
  document.getElementById("hours-all-on").disabled  = !show;
  document.getElementById("hours-all-off").disabled = !show;
  document.getElementById("hours-workday").disabled = !show;
}

document.getElementById("hours-all-on").addEventListener("click", () => {
  setAllHours(true);
});
document.getElementById("hours-all-off").addEventListener("click", () => {
  setAllHours(false);
});
document.getElementById("hours-workday").addEventListener("click", () => {
  // Lunes a viernes, 07:00-20:00
  state.hoursMatrix = state.hoursMatrix.map((day, d) =>
    day.map((_, h) => d >= 1 && d <= 5 && h >= 7 && h < 20)
  );
  refreshGrid();
});

function setAllHours(value) {
  state.hoursMatrix = state.hoursMatrix.map(day => day.map(() => value));
  refreshGrid();
}

function refreshGrid() {
  buildHoursGrid("hours-grid-wrap", state.hoursMatrix, false);
}

document.getElementById("hours-save-btn").addEventListener("click", async () => {
  const clear = document.getElementById("hours-unrestricted-chk").checked;
  const btn   = document.getElementById("hours-save-btn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Guardando…`;

  const body = { dn: state.currentUser.distinguishedName };
  if (clear) {
    body.clear = true;
  } else {
    body.matrix = state.hoursMatrix;
  }

  const data = await api("/api/user/logonhours", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  btn.disabled = false;
  btn.innerHTML = `<i class="bi bi-save me-1"></i>Guardar horarios`;

  if (data.ok) {
    hoursModal.hide();
    toast(data.message, "success");
    // Refrescar detalle del usuario
    selectUser(state.currentUser.sAMAccountName, null);
  } else {
    toast(data.error || data.message, "danger");
  }
});

// ─── Habilitar / Deshabilitar ─────────────────────────────────────────────
async function toggleUser(u) {
  const enable = !u.enabled;
  const action = enable ? "habilitar" : "deshabilitar";
  if (!confirm(`¿Seguro que deseas ${action} la cuenta de ${u.sAMAccountName}?`)) return;

  const data = await api("/api/user/enable", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dn: u.distinguishedName, enable }),
  });
  if (data.ok) {
    toast(data.message, "success");
    selectUser(u.sAMAccountName, null);
  } else {
    toast(data.error || data.message, "danger");
  }
}

// ─── Desbloquear ──────────────────────────────────────────────────────────
async function unlockUser(u) {
  const data = await api("/api/user/unlock", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dn: u.distinguishedName }),
  });
  if (data.ok) {
    toast(data.message, "success");
    selectUser(u.sAMAccountName, null);
  } else {
    toast(data.error || data.message, "danger");
  }
}

// ─── Utilidades de UI ─────────────────────────────────────────────────────
function showAlert(el, type, msg) {
  el.className = `alert alert-${type}`;
  el.textContent = msg;
}

// ─── Botón refrescar árbol ─────────────────────────────────────────────────
document.getElementById("tree-btn").addEventListener("click", () => loadTree());


// ─── Gestión de acceso (solo Administradores) ─────────────────────────────
async function loadAccessProfiles() {
  if (!perms.is_access_manager) return;
  const body = document.getElementById("access-members-body");
  if (!body) return;
  body.innerHTML = `<tr><td colspan="4" class="text-center text-muted">Cargando...</td></tr>`;

  const data = await api("/api/access/profiles");
  if (!data.ok) {
    body.innerHTML = `<tr><td colspan="4" class="text-danger">${escHtml(data.error || "Error")}</td></tr>`;
    return;
  }

  const rows = [];
  for (const [profile, info] of Object.entries(data.profiles)) {
    const members = info.members || [];
    if (!members.length) {
      rows.push(`<tr><td>${escHtml(profile)}</td><td colspan="2" class="text-muted">Sin miembros</td><td></td></tr>`);
      continue;
    }
    members.forEach(m => {
      rows.push(`<tr>
        <td>${escHtml(profile)}<br><small class="text-muted">${escHtml(info.group)}</small></td>
        <td>${escHtml(m.sAMAccountName || "")}</td>
        <td>${escHtml(m.displayName || "")}</td>
        <td><button class="btn btn-sm btn-outline-danger access-remove" data-profile="${escHtml(profile)}" data-sam="${escHtml(m.sAMAccountName || "")}">Quitar</button></td>
      </tr>`);
    });
  }
  body.innerHTML = rows.join("") || `<tr><td colspan="4" class="text-muted">Sin datos</td></tr>`;

  document.querySelectorAll(".access-remove").forEach(btn => {
    btn.addEventListener("click", async () => {
      const profile = btn.dataset.profile;
      const sam = btn.dataset.sam;
      const res = await api("/api/access/profiles/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile, sam }),
      });
      if (res.ok) {
        toast(res.message || "Usuario removido", "success");
        loadAccessProfiles();
      } else {
        toast(res.error || res.message || "Error", "danger");
      }
    });
  });
}

function bindAccessEvents() {
  if (!perms.is_access_manager) return;
  const refresh = document.getElementById("access-refresh-btn");
  const assign = document.getElementById("access-assign-btn");
  const inputSam = document.getElementById("access-sam");
  const select = document.getElementById("access-profile");
  const modal = document.getElementById("accessModal");

  if (refresh) refresh.addEventListener("click", () => loadAccessProfiles());
  if (assign) assign.addEventListener("click", async () => {
    const sam = (inputSam.value || "").trim();
    const profile = (select.value || "").trim();
    if (!sam) {
      toast("Ingresa un usuario", "warning");
      return;
    }
    const data = await api("/api/access/profiles/assign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile, sam }),
    });
    if (data.ok) {
      toast(data.message || "Perfil actualizado", "success");
      inputSam.value = "";
      loadAccessProfiles();
    } else {
      toast(data.error || data.message || "Error", "danger");
    }
  });

  if (modal) {
    modal.addEventListener("shown.bs.modal", () => loadAccessProfiles());
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────
bindAccessEvents();
checkConnection();
