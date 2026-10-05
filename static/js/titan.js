/* ==========================================================================
   TiTaN Panel — front-end runtime
   • sidebar / dropdown plumbing
   • modal system (open by trigger, submit over fetch, toast feedback)
   • traffic chart + donut renderers (match the reference dashboard exactly)
   • copy-to-clipboard, confirm actions, live counters
   ========================================================================== */
(function () {
  "use strict";

  const T = {};

  /* ── helpers ─────────────────────────────────────────────────────────── */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const FA_DIGITS = ["۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹"];

  T.fa = (value) => String(value).replace(/\d/g, (d) => FA_DIGITS[+d]);

  T.humanBytes = function (value, precision) {
    value = Number(value) || 0;
    if (value <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    const p = precision === undefined ? (index < 2 ? 0 : 1) : precision;
    return value.toFixed(p).replace(/\.0+$/, "") + " " + units[index];
  };

  T.debounce = (fn, wait) => {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), wait || 200);
    };
  };

  T.escapeHtml = (text) =>
    String(text === null || text === undefined ? "" : text).replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));

  /* ── toasts ──────────────────────────────────────────────────────────── */
  T.toast = function (message, kind) {
    const wrap = $("#toastWrap");
    if (!wrap) return;
    const node = document.createElement("div");
    node.className = "toast " + (kind || "ok");
    node.innerHTML = T.escapeHtml(message);
    wrap.appendChild(node);
    setTimeout(() => {
      node.style.transition = "opacity .3s, transform .3s";
      node.style.opacity = "0";
      node.style.transform = "translateY(8px)";
      setTimeout(() => node.remove(), 320);
    }, 3600);
  };

  /* ── clipboard ───────────────────────────────────────────────────────── */
  T.copy = async function (text) {
    try {
      await navigator.clipboard.writeText(text);
      T.toast("کپی شد", "ok");
    } catch (err) {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        T.toast("کپی شد", "ok");
      } catch (e) {
        T.toast("کپی ناموفق بود", "err");
      }
      area.remove();
    }
  };

  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-copy]");
    if (!target) return;
    event.preventDefault();
    T.copy(target.getAttribute("data-copy"));
  });

  /* ── dropdowns ───────────────────────────────────────────────────────── */
  function closeAllDropdowns(except) {
    $$(".dropdown.show").forEach((node) => {
      if (node !== except) node.classList.remove("show");
    });
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-dropdown]");
    if (trigger) {
      const panel = $(trigger.getAttribute("data-dropdown"));
      if (panel) {
        const willShow = !panel.classList.contains("show");
        closeAllDropdowns(panel);
        panel.classList.toggle("show", willShow);
        event.stopPropagation();
        return;
      }
    }
    if (!event.target.closest(".dropdown")) closeAllDropdowns();
  });

  document.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-segment-switch]");
    if (!toggle) return;
    const target = toggle.getAttribute("data-segment-switch");
    if (target) window.location.href = target;
  });

  /* ── sidebar (mobile) ────────────────────────────────────────────────── */
  const menuBtn = $("#menuBtn");
  const sidebar = $("#sidebar");
  if (menuBtn && sidebar) {
    menuBtn.addEventListener("click", () => sidebar.classList.toggle("open"));
    document.addEventListener("click", (event) => {
      if (window.innerWidth > 820) return;
      if (!sidebar.contains(event.target) && event.target !== menuBtn) sidebar.classList.remove("open");
    });
  }

  /* ── refresh + search shortcut ───────────────────────────────────────── */
  const refreshBtn = $("#refreshBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      refreshBtn.animate([{ transform: "rotate(0)" }, { transform: "rotate(360deg)" }], { duration: 500, easing: "ease" });
      setTimeout(() => window.location.reload(), 420);
    });
  }
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      const input = $("#globalSearch");
      if (input) input.focus();
    }
    if (event.key === "Escape") closeAllDropdowns();
  });

  /* ── live health ticker (dashboard + nodes page) ─────────────────────── */
  T.tick = function () {
    const nodes = $$("[data-live-node]");
    if (!nodes.length) return;
    fetch("/api/dashboard", { headers: { "X-Requested-With": "fetch" } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        const stamp = $("#liveStamp");
        if (stamp) stamp.textContent = "آخرین بروزرسانی: " + T.fa(data.time);
        (data.nodes || []).forEach((node) => {
          const card = $('[data-live-node="' + node.id + '"]');
          if (!card) return;
          const set = (key, value) => {
            const el = card.querySelector('[data-live-field="' + key + '"]');
            if (el) el.textContent = value;
          };
          set("cpu", T.fa(node.cpu) + "%");
          set("ram", T.fa(node.ram) + "%");
          set("traffic", T.humanBytes(node.traffic));
          set("ping", T.fa(node.ping) + "ms");
          const bar = card.querySelector('[data-live-bar="cpu"]');
          if (bar) bar.style.width = node.cpu + "%";
          const ramBar = card.querySelector('[data-live-bar="ram"]');
          if (ramBar) ramBar.style.width = node.ram + "%";
        });
      })
      .catch(() => {});
  };
  if (document.querySelector("[data-live-node]")) setInterval(T.tick, 15000);

  /* ── modals ──────────────────────────────────────────────────────────── */
  const backdrop = $("#modalBackdrop");

  T.openModal = function (id) {
    const modal = document.getElementById(id);
    if (!modal || !backdrop) return;
    $$(".modal", backdrop).forEach((node) => (node.hidden = true));
    modal.hidden = false;
    backdrop.classList.add("show");
    const first = modal.querySelector("input:not([type=hidden]),select,textarea");
    if (first) setTimeout(() => first.focus(), 60);
  };

  T.closeModal = function () {
    if (!backdrop) return;
    backdrop.classList.remove("show");
    $$(".modal", backdrop).forEach((node) => (node.hidden = true));
  };

  document.addEventListener("click", (event) => {
    const opener = event.target.closest("[data-modal-open]");
    if (opener) {
      event.preventDefault();
      T.openModal(opener.getAttribute("data-modal-open"));
      return;
    }
    if (event.target.closest("[data-modal-close]")) {
      event.preventDefault();
      T.closeModal();
      return;
    }
    if (backdrop && event.target === backdrop) T.closeModal();
    // per-row modal that needs to be filled from data attributes
    const filler = event.target.closest("[data-modal-fill]");
    if (filler) {
      const modalId = filler.getAttribute("data-modal-fill");
      let payload = {};
      try {
        payload = JSON.parse(filler.getAttribute("data-payload") || "{}");
      } catch (e) {
        payload = {};
      }
      Object.keys(payload).forEach((key) => {
        const field = document.querySelector("#" + modalId + " [name='" + key + "']");
        if (!field) return;
        if (field.type === "checkbox") field.checked = !!payload[key];
        else field.value = payload[key];
      });
      T.openModal(modalId);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") T.closeModal();
  });

  /* ── AJAX forms (modal-driven create/update) ─────────────────────────── */
  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!form.matches("form[data-ajax]")) return;
    event.preventDefault();

    const submitBtn = form.querySelector("[type=submit]");
    const original = submitBtn ? submitBtn.innerHTML : "";
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = "در حال ذخیره…";
    }

    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        headers: { "X-Requested-With": "fetch" },
      });
      const data = await response.json().catch(() => ({}));
      if (response.ok && data.ok) {
        T.toast(data.message || "ذخیره شد", "ok");
        if (data.redirect) {
          setTimeout(() => (window.location.href = data.redirect), 500);
        } else {
          setTimeout(() => window.location.reload(), 500);
        }
      } else {
        T.toast(data.message || "خطا در ذخیره‌سازی", "err");
      }
    } catch (err) {
      T.toast("ارتباط با سرور برقرار نشد", "err");
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = original;
      }
    }
  });

  /* ── confirm + action buttons ────────────────────────────────────────── */
  document.addEventListener("click", async (event) => {
    const trigger = event.target.closest("[data-action]");
    if (!trigger) return;
    const url = trigger.getAttribute("data-action");
    const confirmText = trigger.getAttribute("data-confirm");
    if (confirmText && !window.confirm(confirmText)) return;
    event.preventDefault();

    trigger.classList.add("loading");
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "X-Requested-With": "fetch" },
      });
      const data = await response.json().catch(() => ({}));
      if (response.ok && data.ok) {
        T.toast(data.message || "انجام شد", "ok");
        if (data.reload !== false) setTimeout(() => window.location.reload(), 600);
      } else {
        T.toast(data.message || "عملیات ناموفق بود", "err");
      }
    } catch (err) {
      T.toast("ارتباط با سرور برقرار نشد", "err");
    } finally {
      trigger.classList.remove("loading");
    }
  });

  /* ── per-field conditional visibility inside modals ──────────────────── */
  T.bindConditionals = function (root) {
    $$("[data-show-when]", root || document).forEach((target) => {
      const spec = target.getAttribute("data-show-when");     // e.g. "protocol=vless,vmess"
      const [fieldName, values] = spec.split("=");
      const valuesList = (values || "").split(",").map((v) => v.trim());
      const controller = document.querySelector("[name='" + fieldName + "']");
      if (!controller) return;
      const apply = () => {
        const matches = valuesList.includes(controller.value);
        target.hidden = !matches;
        target.classList.toggle("flex-off", !matches);
      };
      controller.addEventListener("change", apply);
      apply();
    });
  };

  /* ── traffic chart (reference visuals, real data) ────────────────────── */
  T.renderTrafficChart = function (series, options) {
    options = options || {};
    const svg = $("#trafficChart");
    if (!svg || !series || !series.length) return;

    const W = 600;
    const H = 190;
    const padTop = 8;
    const usable = H - 20;
    const max = Math.max(...series.map((point) => point.value), 1);
    const stepX = series.length > 1 ? W / (series.length - 1) : W;
    const yFor = (value) => H - 24 - (value / max) * usable;

    const points = series.map((point, index) => [index * stepX, yFor(point.value)]);

    // smooth-ish polyline through the midpoints of each segment
    let line = `M${points[0][0].toFixed(1)} ${points[0][1].toFixed(1)}`;
    for (let i = 1; i < points.length; i += 1) {
      const [px, py] = points[i - 1];
      const [cx, cy] = points[i];
      const midX = (px + cx) / 2;
      line += ` C${midX.toFixed(1)} ${py.toFixed(1)}, ${midX.toFixed(1)} ${cy.toFixed(1)}, ${cx.toFixed(1)} ${cy.toFixed(1)}`;
    }
    const area = `${line} L${W} ${H} L0 ${H} Z`;

    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.innerHTML = `
      <defs>
        <linearGradient id="titArea" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="#6f5cff" stop-opacity=".30"/>
          <stop offset="1" stop-color="#6f5cff" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <path d="${area}" fill="url(#titArea)"/>
      <path d="${line}" fill="none" stroke="#7564ff" stroke-width="2.2" stroke-linecap="round"/>
      <g fill="#7564ff">
        ${points.map(([x, y]) => `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5"/>`).join("")}
      </g>`;

    // y axis
    const ylabels = $("#trafficYLabels");
    if (ylabels) {
      ylabels.innerHTML = [1, 0.75, 0.5, 0.25, 0].map((ratio) => `<span>${T.humanBytes(max * ratio, 0)}</span>`).join("");
    }
    // x axis
    const xlabels = $("#trafficXLabels");
    if (xlabels) {
      xlabels.innerHTML = series.map((point) => `<span>${T.escapeHtml(point.label)}</span>`).join("");
    }
  };

  /* ── donut ───────────────────────────────────────────────────────────── */
  T.renderDonut = function (segments) {
    const donut = $("#trafficDonut");
    if (!donut || !segments || !segments.length) return;
    const total = segments.reduce((sum, item) => sum + item.value, 0);
    if (total <= 0) {
      donut.style.background = "conic-gradient(#1b2740 0 100%)";
      return;
    }
    let cursor = 0;
    const stops = segments
      .filter((item) => item.value > 0)
      .map((item) => {
        const start = cursor;
        cursor += (item.value / total) * 100;
        return `${item.color} ${start.toFixed(2)}% ${cursor.toFixed(2)}%`;
      });
    if (cursor < 100) stops.push(`#1b2740 ${cursor.toFixed(2)}% 100%`);
    donut.style.background = `conic-gradient(${stops.join(",")})`;
  };

  /* ── sparkline for node cards ────────────────────────────────────────── */
  T.renderSpark = function (node, values) {
    if (!node || !values || values.length < 2) return;
    const max = Math.max(...values, 1);
    const step = 100 / (values.length - 1);
    const path = values
      .map((value, index) => `${index === 0 ? "M" : "L"}${(index * step).toFixed(1)} ${(28 - (value / max) * 24).toFixed(1)}`)
      .join(" ");
    node.setAttribute("d", path);
  };

  /* ── auto-close flash + reload hint ──────────────────────────────────── */
  document.addEventListener("DOMContentLoaded", function () {
    T.bindConditionals();
    if (window.__TITAN_CHART__) {
      T.renderTrafficChart(window.__TITAN_CHART__.series);
    }
    if (window.__TITAN_DONUT__) {
      T.renderDonut(window.__TITAN_DONUT__);
    }
    document.querySelectorAll("[data-flash]").forEach((el) => {
      setTimeout(() => {
        el.style.transition = "opacity .4s";
        el.style.opacity = "0";
        setTimeout(() => el.remove(), 420);
      }, 4200);
    });
  });

  window.TiTaN = T;
})();
