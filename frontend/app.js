const API_BASE = "";
    let authToken = sessionStorage.getItem("neuralock-token");
    let conversationId = null;

   async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { "Authorization": `Bearer ${authToken}` } : {}),
      ...(options.headers || {}),
    },
  });

  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(body.detail || "Request failed");
  }

  return body;
}
    function rolesFromForm() {
      return [...document.querySelectorAll("#doc-form input[type=checkbox]:checked")]
        .map((box) => box.value);
    }

    async function loadIdentity() {
      const body = await api("/api/identity");
      document.getElementById("identity").textContent =
        `Organisation ${body.organisation_id} · role ${body.role}. The role comes from the server, not this page.`;
      document.getElementById("user-admin").hidden = body.role !== "admin";
    }

    async function loadDocuments() {
      const body = await api("/api/documents");
      const root = document.getElementById("documents");
      root.innerHTML = "";
      if (!body.documents.length) {
        root.innerHTML = "<p>No documents for this role.</p>";
        return;
      }
      for (const item of body.documents) {
        const row = document.createElement("div");
        row.className = "turn";
        row.innerHTML = `<strong></strong><div class="meta"></div>`;
        row.querySelector("strong").textContent = item.title;
        row.querySelector(".meta").textContent = item.allowed_roles.join(", ");
        const button = document.createElement("button");
        button.type = "button";
        button.className = "quiet";
        button.textContent = "Deactivate";
        button.addEventListener("click", async () => {
          document.getElementById("doc-error").textContent = "";
          try {
            await api(`/api/documents/${item.id}`, {
              method: "PATCH",
              body: JSON.stringify({ is_active: false }),
            });
            await Promise.all([loadDocuments(), loadEvents()]);
          } catch (error) {
            document.getElementById("doc-error").textContent = error.message;
          }
        });
        row.append(button);
        root.append(row);
      }
    }

    async function loadEvents() {
      const params = new URLSearchParams({ limit: "20" });
      const risk = document.getElementById("event-risk").value;
      const action = document.getElementById("event-action").value;
      if (risk) params.set("risk_level", risk);
      if (action) params.set("action", action);
      const events = await api(`/api/security/events?${params}`);
      const summary = await api("/api/security/summary");
      document.getElementById("event-summary").textContent =
        `${summary.total} events · ${summary.high_risk} high risk · ${summary.redactions} redactions · ${summary.refusals} refusals`;
      const root = document.getElementById("events");
      root.innerHTML = "";
      if (!events.length) {
        root.innerHTML = "<p>No events yet.</p>";
        return;
      }
      for (const event of events) {
        const row = document.createElement("div");
        row.className = "event";
        row.innerHTML = `<strong class="risk-${event.risk_level}"></strong><div class="meta"></div>`;
        row.querySelector("strong").textContent =
          `${event.action_taken} · ${event.risk_level}`;
        row.querySelector(".meta").textContent = event.reason;
        root.append(row);
      }
    }

    document.getElementById("chat-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = document.getElementById("chat-error");
      error.textContent = "";
      const message = document.getElementById("message").value.trim();
      if (!message) return;
      try {
        const body = await api("/api/chat", {
          method: "POST",
          body: JSON.stringify({ message, conversation_id: conversationId }),
        });
        conversationId = body.conversation_id;
        const transcript = document.getElementById("transcript");
        const user = document.createElement("div");
        user.className = "turn";
        user.innerHTML = "<strong>You</strong><div></div>";
        user.querySelector("div").textContent = message;
        const assistant = document.createElement("div");
        assistant.className = "turn";
        assistant.innerHTML = "<strong>NeuraLock</strong><div></div><div class='meta'></div>";
        assistant.querySelector("div").textContent = body.reply;
        assistant.querySelector(".meta").textContent =
          `${body.action} · ${body.risk}` +
          (body.documents_in_context.length
            ? ` · ${body.documents_in_context.join(", ")}`
            : "");
        transcript.append(user, assistant);
        document.getElementById("message").value = "";
        await loadEvents();
      } catch (err) {
        error.textContent = err.message;
      }
    });

    document.getElementById("doc-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = document.getElementById("doc-error");
      error.textContent = "";
      const roles = rolesFromForm();
      if (!roles.length) {
        error.textContent = "Choose at least one role.";
        return;
      }
      try {
        await api("/api/documents", {
          method: "POST",
          body: JSON.stringify({
            title: document.getElementById("doc-title").value.trim(),
            content: document.getElementById("doc-content").value.trim(),
            allowed_roles: roles,
          }),
        });
        document.getElementById("doc-form").reset();
        document.querySelector("#doc-form input[value=employee]").checked = true;
        document.querySelector("#doc-form input[value=admin]").checked = true;
        await Promise.all([loadDocuments(), loadEvents()]);
      } catch (err) {
        error.textContent = err.message;
      }
    });

    document.getElementById("user-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = document.getElementById("user-error");
      error.textContent = "";
      try {
        await api("/api/users", {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("new-username").value.trim(),
            password: document.getElementById("new-password").value,
            role: document.getElementById("new-role").value,
          }),
        });
        event.target.reset();
        error.textContent = "Account created. Share its initial password securely.";
      } catch (err) { error.textContent = err.message; }
    });

    async function start() {
      const status = await api("/api/auth/status");
      if (!authToken) {
        document.getElementById("auth-panel").hidden = false;
        document.getElementById("app-shell").hidden = true;
        if (status.needs_bootstrap) {
          document.getElementById("auth-title").textContent = "Create the NeuraLock administrator";
          document.getElementById("auth-help").textContent = "First setup only. Use a unique username and a password of at least 12 characters.";
          document.getElementById("auth-org").hidden = false;
          document.getElementById("auth-password").autocomplete = "new-password";
        }
        return;
      }
      try {
        await Promise.all([loadIdentity(), loadDocuments(), loadEvents()]);
        document.getElementById("auth-panel").hidden = true;
        document.getElementById("app-shell").hidden = false;
      } catch (error) {
        authToken = null;
        sessionStorage.removeItem("neuralock-token");
        document.getElementById("auth-panel").hidden = false;
        document.getElementById("app-shell").hidden = true;
        document.getElementById("auth-error").textContent = error.message;
      }
    }

    document.getElementById("auth-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const status = await api("/api/auth/status");
      const payload = {
        username: document.getElementById("auth-username").value.trim(),
        password: document.getElementById("auth-password").value,
      };
      let path = "/api/auth/login";
      if (status.needs_bootstrap) {
        path = "/api/auth/bootstrap";
          payload.organisation_id = document.getElementById("auth-org").value.trim() || "NL0001";
      }
      try {
        const result = await api(path, { method: "POST", body: JSON.stringify(payload) });
        authToken = result.token;
        sessionStorage.setItem("neuralock-token", authToken);
        await start();
      } catch (error) {
        document.getElementById("auth-error").textContent = error.message;
      }
    });

    document.getElementById("logout").addEventListener("click", async () => {
      try { await api("/api/auth/logout", { method: "POST" }); } catch (_) {}
      authToken = null;
      sessionStorage.removeItem("neuralock-token");
      conversationId = null;
      document.getElementById("transcript").replaceChildren();
      await start();
    });
    document.getElementById("event-risk").addEventListener("change", loadEvents);
    document.getElementById("event-action").addEventListener("change", loadEvents);
    start().catch((error) => { document.getElementById("auth-error").textContent = error.message; });
