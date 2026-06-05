// Kensa compliance model — one scan, many framework lenses.
// A scan runs a rule set against an auto-detected CapabilitySet. Each rule's
// transaction is committed (compliant) or rolled_back (non-compliant), or the
// rule is dropped by its `when:` capability gate (N/A). Framework membership is
// per-rule metadata, so the SAME results regroup under CIS / STIG / NIST.

(function () {
  "use strict";

  const SCAN = {
    ranAt: "4/19/2026, 2:36 PM",
    caps: "Ubuntu 24.04 · AppArmor (not SELinux) · auditd absent · ufw firewall",
  };

  // Per-lens aggregates (full scan), authored to reflect different framework coverage.
  const LENSES = {
    cis: {
      label: "CIS", sub: "Level 1 — Server", groupLabel: "CIS section",
      pass: 148, fail: 262, na: 38,
      cats: [
        { name: "Initial Setup", pass: 14, fail: 34 },
        { name: "Services", pass: 26, fail: 40 },
        { name: "Network Configuration", pass: 16, fail: 38 },
        { name: "Host-based Firewall", pass: 0, fail: 26 },
        { name: "Logging & Auditing", pass: 20, fail: 58 },
        { name: "Access, Authentication & Authorization", pass: 52, fail: 52 },
        { name: "System Maintenance", pass: 20, fail: 14 },
      ],
    },
    stig: {
      label: "DISA STIG", sub: "Ubuntu 24.04 · V1R3", groupLabel: "STIG severity",
      pass: 131, fail: 249, na: 31,
      cats: [
        { name: "CAT I — High", pass: 12, fail: 52 },
        { name: "CAT II — Medium", pass: 96, fail: 171 },
        { name: "CAT III — Low", pass: 23, fail: 26 },
      ],
    },
    nist: {
      label: "NIST 800-53", sub: "Rev 5", groupLabel: "control family",
      pass: 205, fail: 303, na: 44,
      cats: [
        { name: "AC — Access Control", pass: 58, fail: 64 },
        { name: "AU — Audit & Accountability", pass: 20, fail: 70 },
        { name: "CM — Configuration Management", pass: 34, fail: 40 },
        { name: "IA — Identification & Authentication", pass: 30, fail: 28 },
        { name: "SC — System & Communications", pass: 31, fail: 48 },
        { name: "SI — System & Information Integrity", pass: 22, fail: 33 },
        { name: "CP — Contingency Planning", pass: 10, fail: 20 },
      ],
    },
    all: {
      label: "All rules", sub: "every mapped control", groupLabel: "CIS section",
      pass: 184, fail: 324, na: 52,
      cats: [
        { name: "Initial Setup", pass: 18, fail: 42 },
        { name: "Services", pass: 32, fail: 48 },
        { name: "Network Configuration", pass: 20, fail: 45 },
        { name: "Host-based Firewall", pass: 0, fail: 30 },
        { name: "Logging & Auditing", pass: 25, fail: 70 },
        { name: "Access, Authentication & Authorization", pass: 64, fail: 66 },
        { name: "System Maintenance", pass: 25, fail: 23 },
      ],
    },
  };

  const ORDER = ["cis", "stig", "nist", "all"];

  // Representative sample of per-rule results. refs holds framework metadata —
  // a rule appears in a lens only if it carries that framework's ref.
  const RULES = [
    { title: "Disable SSH root login", detail: "PermitRootLogin is set to <code>yes</code> in sshd_config; should be <code>no</code>.",
      status: "fail", sev: "high", stigSev: "CAT I", cat: "Access, Authentication & Authorization",
      refs: { cis: "CIS-5.2.8", stig: "UBTU-24-411045", nist: "AC-6(2)" }, fixable: true },
    { title: "Ensure host firewall (ufw) is enabled", detail: "ufw is inactive and no nftables ruleset is loaded; host is unfiltered.",
      status: "fail", sev: "high", stigSev: "CAT I", cat: "Host-based Firewall",
      refs: { cis: "CIS-3.5.1.1", stig: "UBTU-24-251010", nist: "SC-7" }, fixable: true },
    { title: "auditd installed and enabled", detail: "auditd service is absent — system-call auditing cannot run on this host.",
      status: "na", naReason: "auditd package not installed (capability gate)", sev: "high", stigSev: "CAT II", cat: "Logging & Auditing",
      refs: { cis: "CIS-4.1.1.1", stig: "UBTU-24-653010", nist: "AU-2" }, fixable: false },
    { title: "SELinux in enforcing mode", detail: "Dropped: host enforces AppArmor, so the SELinux implementation does not apply.",
      status: "na", naReason: "host uses AppArmor, not SELinux (when: selinux gate unmet)", sev: "high", stigSev: "CAT I", cat: "Access, Authentication & Authorization",
      refs: { stig: "UBTU-24-431015", nist: "AC-3(4)" }, fixable: false },
    { title: "AppArmor profiles in enforce mode", detail: "9 profiles are in complain mode; should be enforce.",
      status: "fail", sev: "med", stigSev: "CAT II", cat: "Access, Authentication & Authorization",
      refs: { cis: "CIS-1.3.1.2", nist: "AC-3(4)" }, fixable: true },
    { title: "Password maximum age ≤ 365 days", detail: "PASS_MAX_DAYS is 99999 in login.defs; 2 accounts affected.",
      status: "fail", sev: "med", stigSev: "CAT II", cat: "Access, Authentication & Authorization",
      refs: { cis: "CIS-5.4.1.1", stig: "UBTU-24-411025", nist: "IA-5(1)" }, fixable: true },
    { title: "/tmp mounted with noexec, nodev, nosuid", detail: "/tmp has no hardening flags set.",
      status: "fail", sev: "med", stigSev: "CAT II", cat: "Initial Setup",
      refs: { cis: "CIS-1.1.2.2", stig: "UBTU-24-231015" }, fixable: true, reboot: true },
    { title: "Core dumps restricted", detail: "fs.suid_dumpable = 0 and limits.conf disallows core dumps.",
      status: "pass", sev: "high", stigSev: "CAT II", cat: "Initial Setup",
      refs: { cis: "CIS-1.6.1", nist: "SI-11" }, fixable: false },
    { title: "AIDE file-integrity tool installed", detail: "Dropped: aide package is not installed on this host.",
      status: "na", naReason: "aide package not installed (capability gate)", sev: "med", stigSev: "CAT II", cat: "Logging & Auditing",
      refs: { cis: "CIS-1.5.1", nist: "SI-7" }, fixable: false },
    { title: "Time synchronization configured", detail: "systemd-timesyncd active but no upstream NTP servers set.",
      status: "fail", sev: "med", stigSev: "CAT III", cat: "Services",
      refs: { cis: "CIS-2.2.1.1", stig: "UBTU-24-251020", nist: "AU-8(1)" }, fixable: true },
    { title: "Authorized-use banner in MOTD", detail: "/etc/motd is empty. Exception requested — awaiting approval.",
      status: "fail", sev: "low", stigSev: "CAT III", cat: "Initial Setup",
      refs: { cis: "CIS-1.7.1", stig: "UBTU-24-291010" }, fixable: true, exception: true },
    { title: "SSH MaxAuthTries ≤ 4", detail: "MaxAuthTries is unset (defaults to 6).",
      status: "fail", sev: "med", stigSev: "CAT II", cat: "Access, Authentication & Authorization",
      refs: { cis: "CIS-5.2.5", stig: "UBTU-24-411035", nist: "AC-7" }, fixable: true },
    { title: "Disable wireless interfaces when unused", detail: "2 wireless radios active (wlp3s0, wlp4s0).",
      status: "fail", sev: "high", stigSev: "CAT II", cat: "Network Configuration",
      refs: { cis: "CIS-3.1.2", stig: "UBTU-24-251030" }, fixable: true },
    { title: "Password hashing uses SHA-512/yescrypt", detail: "ENCRYPT_METHOD is YESCRYPT — compliant.",
      status: "pass", sev: "med", stigSev: "CAT II", cat: "Access, Authentication & Authorization",
      refs: { cis: "CIS-5.4.3", nist: "IA-5(1)" }, fixable: false },
    { title: "Audit log files mode 0600", detail: "Permissions on /var/log/audit/*.log are 0644; should be 0600.",
      status: "fail", sev: "med", stigSev: "CAT II", cat: "Logging & Auditing",
      refs: { cis: "CIS-4.1.4.1", stig: "UBTU-24-653020", nist: "AU-9" }, fixable: true },
    { title: "cron daemon enabled and running", detail: "cron.service is active and enabled — compliant.",
      status: "pass", sev: "low", stigSev: "CAT III", cat: "Services",
      refs: { cis: "CIS-2.4.1.1" }, fixable: false },
  ];

  const REF_ORDER = ["cis", "stig", "nist"];

  function pct(p, f) { return p + f === 0 ? 0 : Math.round((p / (p + f)) * 100); }
  function tier(v) { return v < 40 ? "crit" : v < 80 ? "warn" : "ok"; }
  function inLens(rule, lensId) { return lensId === "all" ? true : !!rule.refs[lensId]; }

  function lensScore(lensId) {
    const l = LENSES[lensId];
    return pct(l.pass, l.fail);
  }

  function sevTagFor(rule, lensId) {
    if (lensId === "stig") {
      const map = { "CAT I": "high", "CAT II": "med", "CAT III": "low" };
      return { cls: map[rule.stigSev], label: rule.stigSev };
    }
    return { cls: rule.sev, label: rule.sev === "high" ? "High" : rule.sev === "med" ? "Med" : "Low" };
  }

  // ---------- Renderers ----------
  function renderLensBar(active) {
    const bar = document.getElementById("lens-bar");
    if (!bar) return;
    let html = '<span class="lens-label">View as</span>';
    ORDER.forEach((id) => {
      const l = LENSES[id], s = lensScore(id);
      html +=
        '<button class="lens-chip' + (id === active ? " active" : "") + '" data-lens="' + id + '">' +
          '<span class="lens-name">' + l.label + '<span class="lens-sub">' + l.sub + "</span></span>" +
          '<span class="lens-score">' + s + "%</span>" +
        "</button>";
    });
    bar.innerHTML = html;
    bar.querySelectorAll(".lens-chip").forEach((c) =>
      c.addEventListener("click", () => render(c.dataset.lens))
    );
  }

  function renderSummary(lensId) {
    const el = document.getElementById("comp-summary");
    if (!el) return;
    const l = LENSES[lensId];
    const score = pct(l.pass, l.fail);
    const total = l.pass + l.fail;
    const t = tier(score);
    const C = 2 * Math.PI * 46;
    const dash = (score / 100) * C;
    const ringColor = t === "crit" ? "var(--crit)" : t === "warn" ? "var(--warn)" : "var(--ok)";

    el.style.padding = "0";
    el.innerHTML =
      '<div class="score-card">' +
        '<div class="score-ring">' +
          '<svg width="110" height="110"><circle class="ring-bg" cx="55" cy="55" r="46"/>' +
          '<circle class="ring-fg" cx="55" cy="55" r="46" stroke="' + ringColor + '" stroke-dasharray="' + dash.toFixed(1) + " " + (C - dash).toFixed(1) + '"/></svg>' +
          '<div class="center"><div><div class="num" style="color:' + ringColor + '">' + score + '%</div><div class="lbl">Compliant</div></div></div>' +
        "</div>" +
        '<div class="score-side">' +
          '<div class="row-stat"><span class="k">Compliant</span><span class="v pass">' + l.pass + "</span></div>" +
          '<div class="row-stat"><span class="k">Non-compliant</span><span class="v fail">' + l.fail + "</span></div>" +
          '<div class="row-stat"><span class="k">Not applicable</span><span class="v na">' + l.na + "</span></div>" +
          '<div class="row-stat"><span class="k">Executed</span><span class="v">' + total + "</span></div>" +
        "</div>" +
      "</div>" +
      // Severity distribution card (reuses authored cats only for STIG; otherwise a compact note)
      '<div class="panel-card">' +
        "<h4>Result mix · " + l.label + "</h4>" +
        '<div class="sev-bars">' +
          sevBar("ok", "Compliant", l.pass, total, "var(--ok)") +
          sevBar("crit", "Non-compliant", l.fail, total, "var(--crit)") +
        "</div>" +
        '<div class="na-callout"><span class="ico"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg></span>' +
          "<span><strong>" + l.na + " rules not applicable</strong> — dropped by capability gates. " +
          "SELinux rules skipped (host uses AppArmor); auditd & AIDE rules skipped (packages absent).</span></div>" +
      "</div>" +
      // Scan meta
      '<div class="panel-card">' +
        "<h4>Scan</h4>" +
        '<dl class="deflist" style="grid-template-columns:120px 1fr; row-gap:8px; font-size:12px;">' +
          "<dt>Framework</dt><dd>" + l.label + " <span style=\"color:var(--fg-3)\">" + l.sub + "</span></dd>" +
          "<dt>Ran</dt><dd>" + SCAN.ranAt + '<span class="sub">Duration 47s</span></dd>' +
          "<dt>Capabilities</dt><dd style=\"line-height:1.5\">" + SCAN.caps + "</dd>" +
          "<dt>Coverage</dt><dd>" + total + " of this host's rules carry a " + l.label + " ref</dd>" +
        "</dl>" +
      "</div>";
  }

  function sevBar(cls, label, n, total, color) {
    const w = total === 0 ? 0 : Math.round((n / total) * 100);
    return (
      '<div class="sev-bar"><span class="lbl" style="color:' + color + '">' + label + "</span>" +
      '<div class="track"><span class="fail-fill" style="width:' + w + "%; background:" + color + '"></span></div>' + +
      '<span class="count"><span class="fail-n" style="color:' + color + '">' + n + "</span></span></div>"
    );
  }

  function renderCats(lensId) {
    const el = document.getElementById("comp-cats");
    if (!el) return;
    const l = LENSES[lensId];
    let rows = "";
    l.cats.forEach((c, i) => {
      const total = c.pass + c.fail;
      const p = pct(c.pass, c.fail);
      const t = tier(p);
      rows +=
        '<div class="cat-row">' +
          '<div class="cat-name"><span class="num">' + (i + 1) + "</span>" + c.name + "</div>" +
          '<div class="stack"><span class="pass" style="width:' + (total ? (c.pass / total) * 100 : 0) + '%"></span><span class="fail" style="width:' + (total ? (c.fail / total) * 100 : 0) + '%"></span></div>' +
          '<div class="cat-counts"><span class="pass-c">' + c.pass + "</span> / <span class=\"fail-c\">" + c.fail + "</span></div>" +
          '<div class="cat-pct ' + t + '">' + p + "%</div>" +
        "</div>";
    });
    el.style.padding = "0";
    el.style.margin = "18px 0 0";
    el.innerHTML =
      '<div style="padding:14px 18px; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--line);">' +
        '<h3 style="margin:0; font-size:14px; font-weight:600;">By ' + l.groupLabel + "</h3>" +
        '<span style="color:var(--fg-3); font-size:12px;">Grouping follows the active framework</span>' +
      "</div>" +
      '<div class="cat-list">' + rows + "</div>";
  }

  function renderRules(lensId) {
    const el = document.getElementById("comp-rules");
    if (!el) return;
    const l = LENSES[lensId];
    const rows = RULES.filter((r) => inLens(r, lensId));
    let body = "";
    rows.forEach((r) => {
      const st = r.status;
      const stCls = st === "pass" ? "pass" : st === "fail" ? "fail" : "na";
      const stLabel = st === "pass" ? "Compliant" : st === "fail" ? "Non-compliant" : "N/A";
      const sev = sevTagFor(r, lensId);
      let refs = "";
      REF_ORDER.forEach((fw) => {
        if (r.refs[fw]) {
          const dim = lensId !== "all" && lensId !== fw ? " dim" : "";
          refs += '<span class="ref-chip ' + fw + dim + '">' + r.refs[fw] + "</span>";
        }
      });
      const detail = st === "na"
        ? '<div class="rule-sub" style="color:var(--fg-3)">' + r.naReason + "</div>"
        : '<div class="rule-sub">' + r.detail + "</div>";
      const action = st === "fail" && r.fixable
        ? '<button class="btn sm" style="background:var(--info); border-color:var(--info); color:#0a1424; font-weight:600;">Fix</button>'
        : "";
      const excTag = r.exception ? ' <span class="ref-chip" style="background:var(--warn-bg); color:var(--warn)">exception pending</span>' : "";
      body +=
        '<tr class="' + (st === "na" ? "na-row" : "") + '">' +
          '<td><input type="checkbox" class="cb"' + (st === "na" ? " disabled" : "") + "/></td>" +
          '<td><span class="status-cell-c ' + stCls + '"><span class="pip"></span><span class="lbl">' + stLabel + "</span></span></td>" +
          '<td><span class="sev-tag ' + sev.cls + '">' + sev.label + "</span></td>" +
          "<td><div class=\"rule-title\">" + r.title + excTag + "</div>" + detail +
            '<div class="ref-chips" style="margin-top:6px;">' + refs + "</div></td>" +
          '<td><span style="color:var(--fg-2); font-size:12px;">' + r.cat + "</span></td>" +
          '<td class="rule-actions">' + action +
            '<button class="icon-btn" style="width:28px; height:28px;" title="More"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/></svg></button></td>' +
        "</tr>";
    });
    const executed = l.pass + l.fail;
    el.style.margin = "18px 0 0";
    el.innerHTML =
      '<div class="rules-toolbar">' +
        '<div class="search"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><input placeholder="Search rules or framework IDs…"/></div>' +
        '<div class="chips">' +
          '<button class="chip fail active"><span class="dot"></span>Non-compliant <span class="n">' + l.fail + "</span></button>" +
          '<button class="chip pass"><span class="dot"></span>Compliant <span class="n">' + l.pass + "</span></button>" +
          '<button class="chip"><span class="dot" style="background:var(--fg-3)"></span>N/A <span class="n">' + l.na + "</span></button>" +
        "</div>" +
        '<div style="flex:1"></div>' +
        '<span style="color:var(--fg-3); font-size:12px;">' + rows.length + " of " + executed + " " + l.label + " rules</span>" +
      "</div>" +
      '<table class="rules-tbl"><thead><tr>' +
        '<th style="width:28px;"><input type="checkbox" class="cb"/></th>' +
        "<th style=\"width:120px;\">Status</th><th style=\"width:70px;\">Severity</th><th>Rule &amp; framework refs</th><th style=\"width:160px;\">Category</th><th style=\"width:90px; text-align:right;\"></th>" +
      "</tr></thead><tbody>" + body + "</tbody></table>";
  }

  function render(lensId) {
    renderLensBar(lensId);
    renderSummary(lensId);
    renderCats(lensId);
    renderRules(lensId);
  }

  function init() {
    if (!document.getElementById("lens-bar")) return;
    render("cis");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
