// Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
// Hyperion Dashboard — Pure JavaScript frontend for real-time security monitoring.

(function () {
  "use strict";

  // =========================================================================
  // Constants
  // =========================================================================

  const SEVERITY_COLORS = {
    critical: "#ff0040",
    high:     "#ff6600",
    medium:   "#ffaa00",
    low:      "#00aaff",
    info:     "#666680",
  };

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const STATUS_LABELS  = { new: "NEW", investigating: "INVESTIGATING", remediated: "REMEDIATED" };
  const SECURE_COLOR   = "#00ff88";
  const WS_RECONNECT_BASE = 1000;
  const WS_RECONNECT_MAX  = 30000;
  const MAX_FINDINGS_DISPLAY = 200;

  // =========================================================================
  // State
  // =========================================================================

  let ws = null;
  let wsReconnectDelay = WS_RECONNECT_BASE;
  let findings = [];
  let stats = { total: 0, by_severity: {}, by_status: {}, by_surface: {}, risk_score: 0 };
  let timeline = [];
  let filters = { severity: "", category: "", status: "" };
  let alertSoundEnabled = false;
  let selectedFinding = null;

  // =========================================================================
  // DOM refs (populated on DOMContentLoaded)
  // =========================================================================

  let $findingsFeed, $filterSeverity, $filterCategory, $filterStatus;
  let $countCritical, $countHigh, $countMedium, $countLow, $countTotal, $countRisk;
  let $connectionDot, $connectionText;
  let $gaugeCanvas, $donutCanvas, $timelineCanvas, $surfaceCanvas;
  let $codeOverlay, $codeViewer;
  let $alertToggle;

  // =========================================================================
  // Initialization
  // =========================================================================

  document.addEventListener("DOMContentLoaded", function () {
    cacheDOM();
    bindEvents();
    initCanvases();
    connectWebSocket();
    // Redraw canvases on resize
    window.addEventListener("resize", debounce(initCanvases, 200));
  });

  function cacheDOM() {
    $findingsFeed   = document.getElementById("findings-feed");
    $filterSeverity = document.getElementById("filter-severity");
    $filterCategory = document.getElementById("filter-category");
    $filterStatus   = document.getElementById("filter-status");
    $countCritical  = document.getElementById("count-critical");
    $countHigh      = document.getElementById("count-high");
    $countMedium    = document.getElementById("count-medium");
    $countLow       = document.getElementById("count-low");
    $countTotal     = document.getElementById("count-total");
    $countRisk      = document.getElementById("count-risk");
    $connectionDot  = document.getElementById("connection-dot");
    $connectionText = document.getElementById("connection-text");
    $gaugeCanvas    = document.getElementById("gauge-canvas");
    $donutCanvas    = document.getElementById("donut-canvas");
    $timelineCanvas = document.getElementById("timeline-canvas");
    $surfaceCanvas  = document.getElementById("surface-canvas");
    $codeOverlay    = document.getElementById("code-overlay");
    $codeViewer     = document.getElementById("code-viewer");
    $alertToggle    = document.getElementById("alert-toggle");
  }

  function bindEvents() {
    if ($filterSeverity) $filterSeverity.addEventListener("change", onFilterChange);
    if ($filterCategory) $filterCategory.addEventListener("change", onFilterChange);
    if ($filterStatus)   $filterStatus.addEventListener("change", onFilterChange);
    if ($codeOverlay)    $codeOverlay.addEventListener("click", function (e) {
      if (e.target === $codeOverlay) closeCodeViewer();
    });
    if ($alertToggle) $alertToggle.addEventListener("click", function () {
      alertSoundEnabled = !alertSoundEnabled;
      $alertToggle.textContent = alertSoundEnabled ? "ALERTS: ON" : "ALERTS: OFF";
      $alertToggle.style.color = alertSoundEnabled ? SECURE_COLOR : "#555570";
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") closeCodeViewer();
    });
  }

  // =========================================================================
  // WebSocket
  // =========================================================================

  function connectWebSocket() {
    var protocol = location.protocol === "https:" ? "wss:" : "ws:";
    var url = protocol + "//" + location.host + "/ws";
    ws = new WebSocket(url);

    ws.onopen = function () {
      wsReconnectDelay = WS_RECONNECT_BASE;
      setConnectionStatus(true);
    };

    ws.onclose = function () {
      setConnectionStatus(false);
      scheduleReconnect();
    };

    ws.onerror = function () {
      setConnectionStatus(false);
    };

    ws.onmessage = function (event) {
      var msg;
      try { msg = JSON.parse(event.data); } catch (_) { return; }
      handleMessage(msg);
    };

    // Ping every 25s to keep alive
    setInterval(function () {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping" }));
      }
    }, 25000);
  }

  function scheduleReconnect() {
    setTimeout(function () {
      wsReconnectDelay = Math.min(wsReconnectDelay * 2, WS_RECONNECT_MAX);
      connectWebSocket();
    }, wsReconnectDelay);
  }

  function setConnectionStatus(connected) {
    if ($connectionDot) {
      $connectionDot.className = "connection-dot " + (connected ? "connected" : "disconnected");
    }
    if ($connectionText) {
      $connectionText.textContent = connected ? "LIVE" : "RECONNECTING...";
    }
  }

  // =========================================================================
  // Message handling
  // =========================================================================

  function handleMessage(msg) {
    switch (msg.type) {
      case "finding":
        addFinding(msg.data);
        break;
      case "findings_batch":
        msg.data.forEach(function (f) { addFinding(f, true); });
        renderFindingsFeed();
        break;
      case "stats":
        stats = msg.data;
        renderStats();
        drawGauge();
        drawDonut();
        drawSurface();
        break;
      case "timeline":
        timeline = msg.data;
        drawTimeline();
        break;
      case "pong":
        break;
    }
  }

  function addFinding(data, batch) {
    // Avoid duplicates
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].id === data.id) return;
    }
    findings.unshift(data);
    if (findings.length > MAX_FINDINGS_DISPLAY) findings.pop();
    // Sort by severity then timestamp
    findings.sort(function (a, b) {
      var sa = SEVERITY_ORDER[a.severity] || 99;
      var sb = SEVERITY_ORDER[b.severity] || 99;
      if (sa !== sb) return sa - sb;
      return (b.timestamp || 0) - (a.timestamp || 0);
    });
    if (!batch) {
      renderFindingsFeed();
      if (alertSoundEnabled && data.severity === "critical") playAlertSound();
    }
  }

  // =========================================================================
  // Rendering — Stats
  // =========================================================================

  function renderStats() {
    var sev = stats.by_severity || {};
    if ($countCritical) $countCritical.textContent = sev.critical || 0;
    if ($countHigh)     $countHigh.textContent     = sev.high || 0;
    if ($countMedium)   $countMedium.textContent   = sev.medium || 0;
    if ($countLow)      $countLow.textContent      = sev.low || 0;
    if ($countTotal)    $countTotal.textContent     = stats.total || 0;
    if ($countRisk)     $countRisk.textContent      = (stats.risk_score || 0).toFixed(1);
  }

  // =========================================================================
  // Rendering — Findings Feed
  // =========================================================================

  function onFilterChange() {
    filters.severity = $filterSeverity ? $filterSeverity.value : "";
    filters.category = $filterCategory ? $filterCategory.value : "";
    filters.status   = $filterStatus   ? $filterStatus.value   : "";
    renderFindingsFeed();
  }

  function renderFindingsFeed() {
    if (!$findingsFeed) return;
    var filtered = findings.filter(function (f) {
      if (filters.severity && f.severity !== filters.severity) return false;
      if (filters.category && f.category !== filters.category) return false;
      if (filters.status   && f.status   !== filters.status)   return false;
      return true;
    });

    // Populate category filter options dynamically
    if ($filterCategory) {
      var cats = {};
      findings.forEach(function (f) { if (f.category) cats[f.category] = true; });
      var current = $filterCategory.value;
      var opts = '<option value="">All Categories</option>';
      Object.keys(cats).sort().forEach(function (c) {
        opts += '<option value="' + esc(c) + '"' + (c === current ? ' selected' : '') + '>' + esc(c) + '</option>';
      });
      $filterCategory.innerHTML = opts;
    }

    if (filtered.length === 0) {
      $findingsFeed.innerHTML =
        '<div class="empty-state">' +
        '<div class="shield">&#9737;</div>' +
        '<p>No findings match current filters.<br>Awaiting scan results...</p>' +
        '</div>';
      return;
    }

    var html = "";
    filtered.forEach(function (f) {
      html += buildFindingCard(f);
    });
    $findingsFeed.innerHTML = html;

    // Bind click events
    var cards = $findingsFeed.querySelectorAll(".finding-card");
    cards.forEach(function (card) {
      card.addEventListener("click", function () {
        var id = card.getAttribute("data-id");
        var finding = findings.find(function (f) { return f.id === id; });
        if (finding) openCodeViewer(finding);
      });
    });
  }

  function buildFindingCard(f) {
    var sevClass = "severity-" + (f.severity || "info");
    var statusClass = "status-" + (f.status || "new");
    var ts = f.timestamp ? formatTime(f.timestamp) : "";
    var codeSnippet = f.code_context ? highlightPattern(esc(f.code_context), esc(f.pattern_matched)) : "";

    return (
      '<div class="finding-card ' + sevClass + ' ' + statusClass + ' new-entry" data-id="' + esc(f.id) + '">' +
        '<div class="finding-header">' +
          '<span class="severity-badge ' + (f.severity || "info") + '">' + esc(f.severity || "info") + '</span>' +
          '<span class="finding-title">' + esc(f.title || "Untitled Finding") + '</span>' +
          '<span class="finding-status ' + (f.status || "new") + '">' + (STATUS_LABELS[f.status] || "NEW") + '</span>' +
        '</div>' +
        '<div class="finding-meta">' +
          (f.cwe ? '<span class="cwe">' + esc(f.cwe) + '</span>' : '') +
          (f.threat_vector ? '<span class="vector">' + esc(f.threat_vector) + '</span>' : '') +
          (f.file_path ? '<span>' + esc(f.file_path) + (f.line ? ':' + f.line : '') + '</span>' : '') +
        '</div>' +
        (codeSnippet ? '<div class="finding-code">' + codeSnippet + '</div>' : '') +
        '<div class="finding-timestamp">' + ts + '</div>' +
      '</div>'
    );
  }

  // =========================================================================
  // Code Viewer Modal
  // =========================================================================

  function openCodeViewer(f) {
    selectedFinding = f;
    if (!$codeOverlay || !$codeViewer) return;

    var html =
      '<h3>' + esc(f.title || "Finding Details") + '</h3>' +
      '<div style="margin-bottom:12px">' +
        '<span class="severity-badge ' + (f.severity || "info") + '">' + esc(f.severity) + '</span> ' +
        (f.cwe ? '<span style="color:#00aaff;font-family:var(--font-mono);font-size:0.8rem">' + esc(f.cwe) + '</span>' : '') +
      '</div>';

    if (f.description) {
      html += '<p style="color:var(--text-secondary);margin-bottom:12px;font-size:0.85rem">' + esc(f.description) + '</p>';
    }

    if (f.code_context) {
      html +=
        '<div class="code-section">' +
          '<div class="code-section-label">Vulnerable Code</div>' +
          '<pre class="vulnerable">' + highlightPattern(esc(f.code_context), esc(f.pattern_matched)) + '</pre>' +
        '</div>';
    }

    if (f.secure_alternative) {
      html +=
        '<div class="code-section">' +
          '<div class="code-section-label">Secure Alternative</div>' +
          '<pre class="secure">' + esc(f.secure_alternative) + '</pre>' +
        '</div>';
    }

    if (f.remediation) {
      html +=
        '<div class="code-section">' +
          '<div class="code-section-label">Remediation</div>' +
          '<p style="color:var(--text-secondary);font-size:0.82rem;line-height:1.6">' + esc(f.remediation) + '</p>' +
        '</div>';
    }

    html += '<button onclick="window.__hyperionCloseCode()" style="margin-top:12px;background:var(--bg-primary);border:1px solid var(--border);color:var(--text-secondary);padding:6px 16px;border-radius:4px;cursor:pointer;font-family:var(--font-mono)">CLOSE [ESC]</button>';

    $codeViewer.innerHTML = html;
    $codeOverlay.classList.add("active");
  }

  function closeCodeViewer() {
    if ($codeOverlay) $codeOverlay.classList.remove("active");
    selectedFinding = null;
  }

  // Expose for inline onclick
  window.__hyperionCloseCode = closeCodeViewer;

  // =========================================================================
  // Canvas — Risk Score Gauge
  // =========================================================================

  function initCanvases() {
    drawGauge();
    drawDonut();
    drawTimeline();
    drawSurface();
  }

  function drawGauge() {
    var canvas = $gaugeCanvas;
    if (!canvas) return;
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.parentElement.clientWidth || 260;
    var h = Math.min(w * 0.6, 160);
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    var cx = w / 2;
    var cy = h - 16;
    var radius = Math.min(cx - 20, cy - 10);
    var score = Math.min(Math.max(stats.risk_score || 0, 0), 10);

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, radius, Math.PI, 0, false);
    ctx.lineWidth = 14;
    ctx.strokeStyle = "#1a1a2e";
    ctx.lineCap = "round";
    ctx.stroke();

    // Gradient arc
    if (score > 0) {
      var grad = ctx.createLinearGradient(cx - radius, cy, cx + radius, cy);
      grad.addColorStop(0, SECURE_COLOR);
      grad.addColorStop(0.4, "#ffaa00");
      grad.addColorStop(0.7, "#ff6600");
      grad.addColorStop(1, "#ff0040");

      var angle = Math.PI + (score / 10) * Math.PI;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, Math.PI, angle, false);
      ctx.lineWidth = 14;
      ctx.strokeStyle = grad;
      ctx.lineCap = "round";
      ctx.stroke();
    }

    // Needle
    var needleAngle = Math.PI + (score / 10) * Math.PI;
    var needleLen = radius - 20;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(needleAngle) * needleLen, cy + Math.sin(needleAngle) * needleLen);
    ctx.lineWidth = 2;
    ctx.strokeStyle = "#e0e0e8";
    ctx.stroke();

    // Center dot
    ctx.beginPath();
    ctx.arc(cx, cy, 4, 0, Math.PI * 2);
    ctx.fillStyle = "#e0e0e8";
    ctx.fill();

    // Score text
    ctx.font = "bold 24px " + "JetBrains Mono, monospace";
    ctx.fillStyle = scoreColor(score);
    ctx.textAlign = "center";
    ctx.fillText(score.toFixed(1), cx, cy - 20);

    // Label
    ctx.font = "10px " + "JetBrains Mono, monospace";
    ctx.fillStyle = "#555570";
    ctx.fillText("RISK SCORE", cx, cy + 14);

    // Scale labels
    ctx.font = "9px " + "JetBrains Mono, monospace";
    ctx.fillStyle = SECURE_COLOR;
    ctx.textAlign = "left";
    ctx.fillText("0", cx - radius - 4, cy + 14);
    ctx.fillStyle = "#ff0040";
    ctx.textAlign = "right";
    ctx.fillText("10", cx + radius + 4, cy + 14);
  }

  function scoreColor(score) {
    if (score >= 8) return "#ff0040";
    if (score >= 6) return "#ff6600";
    if (score >= 4) return "#ffaa00";
    if (score >= 2) return "#00aaff";
    return SECURE_COLOR;
  }

  // =========================================================================
  // Canvas — Severity Distribution Donut
  // =========================================================================

  function drawDonut() {
    var canvas = $donutCanvas;
    if (!canvas) return;
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.parentElement.clientWidth || 260;
    var h = 180;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    var sev = stats.by_severity || {};
    var slices = [];
    var total = 0;
    ["critical", "high", "medium", "low", "info"].forEach(function (s) {
      var v = sev[s] || 0;
      if (v > 0) slices.push({ severity: s, count: v, color: SEVERITY_COLORS[s] });
      total += v;
    });

    var cx = w / 2;
    var cy = h / 2;
    var outerR = Math.min(cx, cy) - 16;
    var innerR = outerR * 0.6;

    if (total === 0) {
      // Empty state
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
      ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
      ctx.fillStyle = "#1a1a2e";
      ctx.fill();
      ctx.font = "10px JetBrains Mono, monospace";
      ctx.fillStyle = "#555570";
      ctx.textAlign = "center";
      ctx.fillText("NO DATA", cx, cy + 4);
      return;
    }

    var startAngle = -Math.PI / 2;
    slices.forEach(function (slice) {
      var sweep = (slice.count / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, startAngle + sweep);
      ctx.arc(cx, cy, innerR, startAngle + sweep, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = slice.color;
      ctx.fill();
      startAngle += sweep;
    });

    // Center text
    ctx.font = "bold 18px JetBrains Mono, monospace";
    ctx.fillStyle = "#e0e0e8";
    ctx.textAlign = "center";
    ctx.fillText(String(total), cx, cy + 2);
    ctx.font = "9px JetBrains Mono, monospace";
    ctx.fillStyle = "#555570";
    ctx.fillText("FINDINGS", cx, cy + 16);

    // Legend
    var legendY = h - 8;
    var legendX = 8;
    ctx.font = "9px JetBrains Mono, monospace";
    slices.forEach(function (slice) {
      ctx.fillStyle = slice.color;
      ctx.fillRect(legendX, legendY - 7, 8, 8);
      ctx.fillStyle = "#8888a0";
      ctx.textAlign = "left";
      var label = slice.severity.substring(0, 4).toUpperCase() + " " + slice.count;
      ctx.fillText(label, legendX + 11, legendY);
      legendX += ctx.measureText(label).width + 20;
    });
  }

  // =========================================================================
  // Canvas — Timeline Sparkline
  // =========================================================================

  function drawTimeline() {
    var canvas = $timelineCanvas;
    if (!canvas) return;
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.parentElement.clientWidth || 260;
    var h = 100;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    var pad = { top: 8, right: 8, bottom: 16, left: 8 };
    var cw = w - pad.left - pad.right;
    var ch = h - pad.top - pad.bottom;

    if (!timeline || timeline.length === 0) {
      ctx.font = "10px JetBrains Mono, monospace";
      ctx.fillStyle = "#555570";
      ctx.textAlign = "center";
      ctx.fillText("AWAITING TIMELINE DATA", w / 2, h / 2);
      return;
    }

    var maxCount = 1;
    timeline.forEach(function (b) { if (b.count > maxCount) maxCount = b.count; });

    var barW = Math.max(1, (cw / timeline.length) - 1);
    timeline.forEach(function (b, i) {
      var x = pad.left + i * (cw / timeline.length);
      var barH = (b.count / maxCount) * ch;
      // Color by dominant severity
      var color = "#1a1a2e";
      if (b.count > 0) {
        var bySev = b.by_severity || {};
        if (bySev.critical) color = SEVERITY_COLORS.critical;
        else if (bySev.high) color = SEVERITY_COLORS.high;
        else if (bySev.medium) color = SEVERITY_COLORS.medium;
        else if (bySev.low) color = SEVERITY_COLORS.low;
        else color = SEVERITY_COLORS.info;
      }
      ctx.fillStyle = color;
      ctx.fillRect(x, pad.top + ch - barH, barW, barH);
    });

    // Axis label
    ctx.font = "8px JetBrains Mono, monospace";
    ctx.fillStyle = "#555570";
    ctx.textAlign = "center";
    ctx.fillText("FINDINGS OVER TIME (1 MIN BUCKETS)", w / 2, h - 2);
  }

  // =========================================================================
  // Canvas — Attack Surface Map
  // =========================================================================

  function drawSurface() {
    var canvas = $surfaceCanvas;
    if (!canvas) return;
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.parentElement.clientWidth || 280;
    var h = 220;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    var surfaces = ["API", "Auth", "Input", "Config", "Agent", "Crypto", "Network", "Storage"];
    var bySurface = stats.by_surface || {};

    var cx = w / 2;
    var cy = h / 2;
    var radius = Math.min(cx, cy) - 30;

    // Draw connections
    ctx.strokeStyle = "#1a1a2e";
    ctx.lineWidth = 1;
    surfaces.forEach(function (_, i) {
      var angle1 = (i / surfaces.length) * Math.PI * 2 - Math.PI / 2;
      var x1 = cx + Math.cos(angle1) * radius;
      var y1 = cy + Math.sin(angle1) * radius;
      for (var j = i + 1; j < surfaces.length; j++) {
        var angle2 = (j / surfaces.length) * Math.PI * 2 - Math.PI / 2;
        var x2 = cx + Math.cos(angle2) * radius;
        var y2 = cy + Math.sin(angle2) * radius;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }
    });

    // Draw nodes
    surfaces.forEach(function (name, i) {
      var angle = (i / surfaces.length) * Math.PI * 2 - Math.PI / 2;
      var x = cx + Math.cos(angle) * radius;
      var y = cy + Math.sin(angle) * radius;
      var count = 0;
      // Match surface names case-insensitively
      Object.keys(bySurface).forEach(function (key) {
        if (key.toLowerCase() === name.toLowerCase()) count = bySurface[key];
      });

      var nodeColor = "#1a1a2e";
      var nodeRadius = 16;
      if (count > 0) {
        // Severity-like color based on count
        if (count >= 10) { nodeColor = SEVERITY_COLORS.critical; nodeRadius = 22; }
        else if (count >= 5) { nodeColor = SEVERITY_COLORS.high; nodeRadius = 20; }
        else if (count >= 2) { nodeColor = SEVERITY_COLORS.medium; nodeRadius = 18; }
        else { nodeColor = SEVERITY_COLORS.low; nodeRadius = 16; }
      }

      // Glow
      if (count > 0) {
        ctx.beginPath();
        ctx.arc(x, y, nodeRadius + 4, 0, Math.PI * 2);
        ctx.fillStyle = nodeColor.replace(")", ", 0.15)").replace("rgb", "rgba");
        // Use a simpler alpha approach
        ctx.globalAlpha = 0.25;
        ctx.fillStyle = nodeColor;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(x, y, nodeRadius, 0, Math.PI * 2);
      ctx.fillStyle = count > 0 ? nodeColor : "#1a1a2e";
      ctx.fill();
      ctx.strokeStyle = count > 0 ? nodeColor : "#2a2a4e";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Label
      ctx.font = "bold 8px JetBrains Mono, monospace";
      ctx.fillStyle = count > 0 ? "#fff" : "#555570";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(name.toUpperCase(), x, y - (count > 0 ? 3 : 0));
      if (count > 0) {
        ctx.font = "bold 9px JetBrains Mono, monospace";
        ctx.fillText(String(count), x, y + 8);
      }
    });

    // Center label
    ctx.font = "8px JetBrains Mono, monospace";
    ctx.fillStyle = "#555570";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("ATTACK", cx, cy - 5);
    ctx.fillText("SURFACE", cx, cy + 5);
  }

  // =========================================================================
  // Alert Sound
  // =========================================================================

  function playAlertSound() {
    try {
      var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      // Two-tone alert
      [880, 660].forEach(function (freq, i) {
        var osc = audioCtx.createOscillator();
        var gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.frequency.value = freq;
        osc.type = "square";
        gain.gain.value = 0.08;
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.3 + i * 0.15);
        osc.start(audioCtx.currentTime + i * 0.15);
        osc.stop(audioCtx.currentTime + 0.3 + i * 0.15);
      });
    } catch (_) { /* Audio not available */ }
  }

  // =========================================================================
  // Utilities
  // =========================================================================

  function esc(str) {
    if (!str) return "";
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  }

  function highlightPattern(code, pattern) {
    if (!pattern || !code) return code;
    // Simple case-insensitive highlight
    try {
      var escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return code.replace(new RegExp("(" + escaped + ")", "gi"),
        '<span class="matched-pattern">$1</span>');
    } catch (_) {
      return code;
    }
  }

  function formatTime(ts) {
    var d = new Date(ts * 1000);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    return hh + ":" + mm + ":" + ss;
  }

  function debounce(fn, delay) {
    var timer;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, delay);
    };
  }

})();
