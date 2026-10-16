function getCSRF() {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.content : "";
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": getCSRF(),
    },
    credentials: "same-origin",
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await r.json(); } catch {}
  return { status: r.status, data };
}

function bindAuthForm(sel, endpoint, fallbackRedirect, isRegister) {
  const form = document.querySelector(sel);
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = form.querySelector(".err");
    err.textContent = "";
    const fd = new FormData(form);
    const { status, data } = await postJSON(endpoint, {
      email: fd.get("email"),
      password: fd.get("password"),
    });
    if (status === 200 && data.ok) {
      // dev mode — show OTP in sessionStorage before redirect
      if (data.dev_otp) {
        sessionStorage.setItem("dev_otp", data.dev_otp);
      }
      const dest = data.redirect || fallbackRedirect;
      window.location.href = dest;
      return;
    }
    err.textContent = data.error || `Error ${status}`;
  });
}

function bindDashboard() {
  const btn = document.getElementById("new-key");
  const box = document.getElementById("new-key-box");
  const val = document.getElementById("new-key-val");
  if (btn) {
    btn.addEventListener("click", async () => {
      const name = prompt("Key name:", "default") || "default";
      const { status, data } = await postJSON("/api/keys", { name });
      if (status === 200 && data.ok) {
        box.classList.remove("hidden");
        val.textContent = data.key;
      } else {
        alert(data.error || `Error ${status}`);
      }
    });
  }
  document.querySelectorAll(".revoke").forEach((el) => {
    el.addEventListener("click", async () => {
      if (!confirm("Revoke this key?")) return;
      const id = el.dataset.id;
      const { status, data } = await postJSON(`/api/keys/${id}/revoke`, {});
      if (status === 200 && data.ok) location.reload();
      else alert(data.error || "Error");
    });
  });
}

async function bindPayButton() {
  const btn = document.getElementById("confirm-btn");
  if (!btn) return;
  const err = document.getElementById("err");
  const statusMsg = document.getElementById("status-msg");
  const pid = btn.dataset.pid;
  btn.addEventListener("click", async () => {
    err.textContent = "";
    btn.disabled = true;
    btn.textContent = "កំពុងឆែក...";
    statusMsg.textContent = "កំពុងឆែកប្រតិបត្តិការ សូមរង់ចាំ ~5 វិនាទី";
    const { status, data } = await postJSON("/pay/check", { payment_id: parseInt(pid, 10) });
    if (status === 200 && data.ok && (data.activated || data.already_paid)) {
      btn.textContent = "ជោគជ័យ!";
      statusMsg.textContent = "ការជាវសកម្ម — កំពុងបញ្ជូនទៅ dashboard...";
      setTimeout(() => { window.location.href = "/dashboard"; }, 800);
      return;
    }
    btn.disabled = false;
    btn.textContent = "ព្យាយាមម្ដងទៀត";
    err.textContent = data.error || "រកមិនឃើញប្រាក់";
    statusMsg.textContent = "បើទើបបង់ — រង់ចាំ 10 វិនាទី រួចចុចម្ដងទៀត";
  });
}

function bindVerifyPending() {
  const btn = document.getElementById("resend-btn");
  if (!btn) return;
  const err = document.getElementById("err");
  const status = document.getElementById("status");
  const email = btn.dataset.email;
  const cd = document.getElementById("countdown");

  // countdown from server value
  let remaining = cd ? parseInt(cd.textContent, 10) : 0;
  let timer = null;

  function tick() {
    if (remaining <= 0) {
      btn.disabled = false;
      btn.textContent = "ផ្ញើឡើងវិញ";
      if (timer) clearInterval(timer);
      return;
    }
    btn.disabled = true;
    btn.innerHTML = `ផ្ញើឡើងវិញបានក្នុង <span id="countdown">${remaining}</span>s`;
    remaining--;
  }

  if (remaining > 0) {
    timer = setInterval(tick, 1000);
    tick();
  }

  btn.addEventListener("click", async () => {
    err.textContent = "";
    status.textContent = "";
    btn.disabled = true;
    const { status: code, data } = await postJSON("/api/verify/resend", { email });
    if (code === 200 && data.ok) {
      if (data.verified) {
        window.location.href = "/login";
        return;
      }
      status.textContent = data.sent
        ? "✓ ផ្ញើម្ដងទៀតរួចរាល់ — ពិនិត្យ inbox"
        : "SMTP error — ពិនិត្យ log";
      remaining = data.cooldown || 60;
      timer = setInterval(tick, 1000);
      tick();
      return;
    }
    // 429 → wait
    if (code === 429 && data.cooldown) {
      remaining = data.cooldown;
      timer = setInterval(tick, 1000);
      tick();
      return;
    }
    btn.disabled = false;
    btn.textContent = "ផ្ញើឡើងវិញ";
    err.textContent = data.error || "មានបញ្ហា";
  });
}

function bindOtpForm() {
  // dev — display stored OTP
  const storedOtp = sessionStorage.getItem("dev_otp");
  if (storedOtp && window._showDevOtp) {
    window._showDevOtp(storedOtp);
    sessionStorage.removeItem("dev_otp");
  }

  const form = document.getElementById("otp-form");
  if (form) {
    const err = form.querySelector(".err");
    const status = document.getElementById("status");
    const email = form.dataset.email;

    // auto-submit on 6 digits
    const input = form.querySelector('input[name="code"]');
    input.addEventListener("input", (e) => {
      e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.textContent = "";
      status.textContent = "កំពុងផ្ទៀងផ្ទាត់...";
      const code = input.value.trim();
      const { status: httpCode, data } = await postJSON("/api/login/otp", { email, code });
      if (httpCode === 200 && data.ok) {
        status.textContent = "ជោគជ័យ — កំពុងបញ្ជូនទៅ dashboard...";
        window.location.href = data.redirect || "/dashboard";
        return;
      }
      status.textContent = "";
      err.textContent = data.error || "មានបញ្ហា";
      input.select();
    });
  }

  const btn = document.getElementById("resend-otp-btn");
  if (!btn) return;
  const err = document.getElementById("err");
  const status = document.getElementById("status");
  const email = btn.dataset.email;
  const cd = document.getElementById("countdown");
  let remaining = cd ? parseInt(cd.textContent, 10) : 0;
  let timer = null;

  function tick() {
    if (remaining <= 0) {
      btn.disabled = false;
      btn.textContent = "ផ្ញើកូដឡើងវិញ";
      if (timer) clearInterval(timer);
      return;
    }
    btn.disabled = true;
    btn.innerHTML = `ផ្ញើឡើងវិញបានក្នុង <span id="countdown">${remaining}</span>s`;
    remaining--;
  }

  if (remaining > 0) {
    timer = setInterval(tick, 1000);
    tick();
  }

  btn.addEventListener("click", async () => {
    err.textContent = "";
    status.textContent = "";
    btn.disabled = true;
    const { status: httpCode, data } = await postJSON("/api/login/resend-otp", { email });
    if (httpCode === 200 && data.ok) {
      status.textContent = data.sent ? "✓ ផ្ញើកូដថ្មីរួច" : "SMTP មិនបានកំណត់";
      if (data.dev_otp && window._showDevOtp) {
        window._showDevOtp(data.dev_otp);
      }
      remaining = data.cooldown || 60;
      timer = setInterval(tick, 1000);
      tick();
      return;
    }
    if (httpCode === 429 && data.cooldown) {
      remaining = data.cooldown;
      timer = setInterval(tick, 1000);
      tick();
      return;
    }
    btn.disabled = false;
    btn.textContent = "ផ្ញើកូដឡើងវិញ";
    err.textContent = data.error || "មានបញ្ហា";
  });
}

function withLoading(btn, fn) {
  return async (...args) => {
    if (!btn || btn.dataset.busy === "1") return;
    const orig = btn.textContent;
    btn.dataset.busy = "1";
    btn.disabled = true;
    btn.classList.add("btn-loading");
    try {
      return await fn(...args);
    } finally {
      btn.dataset.busy = "0";
      btn.disabled = false;
      btn.classList.remove("btn-loading");
      if (btn.textContent !== orig) btn.textContent = orig;
    }
  };
}

// DEV — display OTP returned by server in console mode
(function() {
  const origPostJSON = window.postJSON;
  // store last OTP and render banner
  window._showDevOtp = function(code) {
    if (!code) return;
    let banner = document.getElementById("dev-otp-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "dev-otp-banner";
      banner.style.cssText = `
        background: #f5a524; color: #000; padding: 14px;
        border-radius: 8px; margin: 16px 0;
        font-family: monospace; font-size: 14px;
        text-align: center; font-weight: 600;
      `;
      const card = document.querySelector(".form-card, .verify-card");
      if (card) card.prepend(banner);
    }
    banner.innerHTML = `⚠ DEV MODE — OTP: <span style="font-size:20px;letter-spacing:4px;">${code}</span>`;
  };
})();
