/* UUID Forge — all randomness from crypto.getRandomValues / crypto.randomUUID. */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;
  var CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  var ALPHA = {
    "A-Za-z0-9_-": "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict", // nanoid's default URL-safe set
    "A-Za-z0-9": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "0-9a-f": "0123456789abcdef",
    "0-9": "0123456789",
    "nolook": "346789ABCDEFGHJKLMNPQRTUVWXYabcdefghijkmnpqrtwxyz"
  };
  var HELP = {
    v4: "Random UUID (RFC 9562 version 4). 122 random bits — the safe default.",
    v7: "Time-ordered UUID (RFC 9562 version 7): a millisecond timestamp then random bits. Sorts by creation time, great for database keys.",
    ulid: "ULID: 26 Crockford Base32 characters, a millisecond timestamp then 80 random bits. Sortable and URL-safe.",
    nano: "NanoID: a compact random ID from your chosen alphabet. 21 URL-safe characters ≈ UUID v4 collision safety."
  };

  function rnd(n) { var b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
  function hexOf(b) { var s = ""; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16); return s; }
  function dash(h) { return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20); }

  function uuid4() {
    if (crypto.randomUUID) return crypto.randomUUID();
    var b = rnd(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; return dash(hexOf(b));
  }

  // UUID v7 with a 12-bit counter in rand_a (RFC 9562 §6.2 method 1) so bulk output is strictly ordered.
  var v7s = { ms: -1, seq: 0 };
  function uuid7(nowMs) {
    var ms = nowMs == null ? Date.now() : nowMs;
    if (ms <= v7s.ms) { v7s.seq++; ms = v7s.ms; if (v7s.seq > 0xfff) { ms = ++v7s.ms; v7s.seq = 0; } }
    else { v7s.ms = ms; v7s.seq = rnd(2)[0] & 0x7f; } // start low so a burst rarely overflows
    var b = rnd(16);
    for (var i = 5; i >= 0; i--) { b[i] = ms % 256; ms = Math.floor(ms / 256); }
    b[6] = 0x70 | ((v7s.seq >> 8) & 0x0f); b[7] = v7s.seq & 0xff;
    b[8] = (b[8] & 0x3f) | 0x80;
    return dash(hexOf(b));
  }

  // ULID, monotonic within the same millisecond (spec: increment the random part).
  var us = { ms: -1, r: null };
  function ulid(nowMs) {
    var ms = nowMs == null ? Date.now() : nowMs;
    if (ms <= us.ms && us.r) {
      ms = us.ms;
      for (var i = 15; i >= 0; i--) { if (us.r[i] < 31) { us.r[i]++; break; } us.r[i] = 0; }
    } else {
      us.ms = ms; us.r = Array.prototype.map.call(rnd(16), function (x) { return x & 31; });
    }
    var t = "", m = ms;
    for (var k = 0; k < 10; k++) { t = CROCKFORD[m % 32] + t; m = Math.floor(m / 32); }
    return t + us.r.map(function (x) { return CROCKFORD[x]; }).join("");
  }

  // Unbiased NanoID: rejection sampling against the largest multiple of the alphabet size.
  function nanoid(len, alphabet) {
    var chars = Array.from(alphabet), n = chars.length, lim = 256 - (256 % n), out = "", got = 0;
    while (got < len) {
      var b = rnd(len * 2);
      for (var i = 0; i < b.length && got < len; i++) if (b[i] < lim) { out += chars[b[i] % n]; got++; }
    }
    return out;
  }

  function inspect(input) {
    var s = String(input).trim();
    if (/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/i.test(s)) {
      var t = 0; for (var i = 0; i < 10; i++) t = t * 32 + CROCKFORD.indexOf(s[i].toUpperCase());
      return { kind: "ULID", ok: true, rows: [["Type", "ULID"], ["Created", new Date(t).toISOString()], ["Timestamp (ms)", String(t)], ["Random part", s.slice(10).toUpperCase()]], ms: t };
    }
    var h = s.replace(/^urn:uuid:/i, "").replace(/^\{|\}$/g, "");
    if (!/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(h)) return { ok: false };
    h = h.replace(/-/g, "").toLowerCase();
    if (h === "00000000000000000000000000000000") return { ok: true, kind: "Nil UUID", version: 0, rows: [["Type", "Nil UUID (all zeros)"]] };
    if (h === "ffffffffffffffffffffffffffffffff") return { ok: true, kind: "Max UUID", version: 15, rows: [["Type", "Max UUID (all ones)"]] };
    var ver = parseInt(h[12], 16), vn = parseInt(h[16], 16);
    var variant = vn < 8 ? "NCS (reserved)" : vn < 12 ? "RFC 9562 / 4122" : vn < 14 ? "Microsoft (reserved)" : "Future (reserved)";
    var names = { 1: "time-based (MAC)", 2: "DCE security", 3: "name-based MD5", 4: "random", 5: "name-based SHA-1", 6: "reordered time", 7: "Unix-time ordered", 8: "custom" };
    var rows = [["Type", "UUID version " + ver + (names[ver] ? " — " + names[ver] : " (unknown)")], ["Variant", variant], ["Canonical", dash(h)]];
    var ms = null;
    if (ver === 7) ms = parseInt(h.slice(0, 12), 16);
    if (ver === 1 || ver === 6) {
      var ts = ver === 1 ? BigInt("0x" + h.slice(13, 16) + h.slice(8, 12) + h.slice(0, 8)) : BigInt("0x" + h.slice(0, 12) + h.slice(13, 16));
      ms = Number((ts - 122192928000000000n) / 10000n);
    }
    if (ms != null) rows.push(["Created", new Date(ms).toISOString()], ["Timestamp (ms)", String(ms)]);
    return { ok: true, kind: "UUID", version: ver, variant: variant, rows: rows, ms: ms };
  }

  // ---------- UI ----------
  var st = { kind: S3.store("uuid.kind") || "v4", ids: [] };
  var count = $("#count"), upper = $("#upper"), nodash = $("#nodash"), nanoLen = $("#nanoLen"), preset = $("#nanoPreset"), alpha = $("#nanoAlpha");
  var saved = S3.store("uuid.opts") || {};
  count.value = saved.count || 10; upper.checked = !!saved.upper; nodash.checked = !!saved.nodash;
  nanoLen.value = saved.nanoLen || 21; preset.value = saved.preset || "A-Za-z0-9_-";
  alpha.value = saved.alpha || ALPHA[preset.value] || ALPHA["A-Za-z0-9_-"];
  function remember() { S3.store("uuid.opts", { count: count.value, upper: upper.checked, nodash: nodash.checked, nanoLen: nanoLen.value, preset: preset.value, alpha: alpha.value }); }

  function nanoAlphabet() { return Array.from(new Set(Array.from(alpha.value))).join(""); }
  function nanoInfo() {
    var a = nanoAlphabet(), n = Array.from(a).length, L = clamp(+nanoLen.value, 2, 128);
    $("#nanoInfo").textContent = n < 2 ? "The alphabet needs at least 2 different characters" : n > 256 ? "Use 256 characters or fewer" :
      n + " characters · " + Math.floor(L * Math.log2(n)) + " bits of randomness" + (n < Array.from(alpha.value).length ? " · duplicates ignored" : "");
  }
  function clamp(v, a, b) { return Math.min(b, Math.max(a, Math.round(v) || a)); }

  function setKind(k) {
    st.kind = k; S3.store("uuid.kind", k);
    $$("#kind button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.v === k)); });
    $("#kindHelp").textContent = HELP[k];
    $("#uuidOpts").hidden = k === "nano";
    $("#nanoOpts").hidden = k !== "nano";
    nodash.disabled = k === "ulid";
    nodash.parentNode.style.opacity = k === "ulid" ? ".4" : "";
    generate();
  }

  function one() {
    if (st.kind === "nano") return nanoid(clamp(+nanoLen.value, 2, 128), nanoAlphabet());
    var id = st.kind === "v4" ? uuid4() : st.kind === "v7" ? uuid7() : ulid();
    if (st.kind !== "ulid" && nodash.checked) id = id.replace(/-/g, "");
    if (st.kind === "ulid") return upper.checked ? id : id.toLowerCase();
    return upper.checked ? id.toUpperCase() : id;
  }

  function generate() {
    var n = clamp(+count.value, 1, 1000);
    count.value = n;
    if (st.kind === "nano") { var na = Array.from(nanoAlphabet()).length; if (na < 2 || na > 256) { nanoInfo(); S3.toast("Fix the alphabet first", "error"); return; } }
    st.ids = [];
    for (var i = 0; i < n; i++) st.ids.push(one());
    var list = $("#list"); list.textContent = "";
    var frag = document.createDocumentFragment();
    st.ids.forEach(function (id) { frag.appendChild(S3.h("li", { tabindex: "0", title: "Click to copy", text: id })); });
    list.appendChild(frag);
    $("#resInfo").textContent = n + (n === 1 ? " ID" : " IDs");
    remember();
  }

  $$("#kind button").forEach(function (b) { b.addEventListener("click", function () { setKind(b.dataset.v); }); });
  $("#gen").addEventListener("click", function () { generate(); S3.done(); });
  document.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { generate(); S3.done(); } });
  [count, upper, nodash, nanoLen].forEach(function (el) { el.addEventListener("change", generate); });
  preset.addEventListener("change", function () { if (ALPHA[preset.value]) alpha.value = ALPHA[preset.value]; else alpha.focus(); nanoInfo(); generate(); });
  alpha.addEventListener("input", function () { preset.value = "custom"; nanoInfo(); });
  alpha.addEventListener("change", generate);
  nanoLen.addEventListener("input", nanoInfo);

  $("#list").addEventListener("click", function (e) { var li = e.target.closest("li"); if (li) S3.copy(li.textContent); });
  $("#list").addEventListener("keydown", function (e) { var li = e.target.closest("li"); if (li && e.key === "Enter") S3.copy(li.textContent); });
  $("#copyAll").addEventListener("click", function () { if (st.ids.length) { S3.copy(st.ids.join("\n"), st.ids.length + " IDs copied"); S3.done(); } });
  $("#save").addEventListener("click", function () { if (st.ids.length) { S3.download(st.ids.join("\n") + "\n", st.kind + "-ids.txt", "text/plain"); S3.done(); } });

  function check() {
    var v = $("#check").value, chip = $("#checkChip"), rows = $("#checkRows");
    rows.textContent = "";
    if (!v.trim()) { chip.className = "chip"; chip.textContent = "Waiting for an ID"; $("#checkWrap").hidden = true; return; }
    var r = inspect(v);
    if (!r.ok) { chip.className = "chip bad"; chip.textContent = "Not a valid UUID or ULID"; $("#checkWrap").hidden = true; return; }
    chip.className = "chip ok"; chip.textContent = "✓ Valid " + (r.kind === "UUID" ? "UUID v" + r.version : r.kind);
    r.rows.forEach(function (x) { rows.appendChild(S3.h("tr", null, [S3.h("th", { text: x[0] }), S3.h("td", { "class": "mono", text: x[1] })])); });
    $("#checkWrap").hidden = false;
  }
  $("#check").addEventListener("input", check);

  nanoInfo();
  setKind(st.kind);

  window.S3_DEMO = function () {
    count.value = 12; setKind("v7");
    $("#check").value = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"; check();
  };

  window.S3_SELFTEST = function () {
    var V = /^[0-9a-f]{8}-[0-9a-f]{4}-([47])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    var a = uuid4(); if (!V.test(a) || a[14] !== "4") return "v4 format";
    var seen = {}, prev = "";
    for (var i = 0; i < 2000; i++) { // same millisecond → must still be strictly increasing
      var u = uuid7(1645557742000);
      if (!V.test(u) || u[14] !== "7" || u <= prev || seen[u]) return "v7 order/format " + u; seen[u] = 1; prev = u;
    }
    var ins = inspect(uuid7(1645557742000 + 99999));
    if (ins.version !== 7 || ins.ms !== 1645557742000 + 99999) return "v7 ts";
    // RFC 9562 appendix A test vectors: all three encode 2022-02-22T19:22:22Z
    if (inspect("017F22E2-79B0-7CC3-98C4-DC0C0C07398F").ms !== 1645557742000) return "rfc v7";
    if (inspect("C232AB00-9414-11EC-B3C8-9F6BDECED846").ms !== 1645557742000) return "rfc v1";
    if (inspect("1EC9414C-232A-6B00-B3C8-9F6BDECED846").ms !== 1645557742000) return "rfc v6";
    if (inspect("{919108f7-52d1-4320-9bac-f847db4148a8}").version !== 4) return "braces v4";
    // ULID spec example
    if (inspect("01ARZ3NDEKTSV4RRFFQ69G5FAV").ms !== 1469922850259) return "ulid decode";
    prev = "";
    for (var j = 0; j < 500; j++) { var l = ulid(1469922850259); if (l.length !== 26 || l <= prev || !l.startsWith("01ARZ3NDEK")) return "ulid mono"; prev = l; }
    var nid = nanoid(21, ALPHA["A-Za-z0-9_-"]); if (nid.length !== 21 || !/^[A-Za-z0-9_-]+$/.test(nid)) return "nanoid";
    if (!/^[ab]{50}$/.test(nanoid(50, "ab"))) return "nanoid alphabet";
    if (Array.from(nanoid(5, "😀😃")).length !== 5) return "nanoid unicode";
    if (inspect("not-a-uuid").ok || inspect("00000000-0000-0000-0000-000000000000").kind !== "Nil UUID") return "validator";
    return true;
  };
})();
