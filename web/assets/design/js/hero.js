/* UltraWideLock — the landing hero: a working DS-TWR round.
 *
 * The page opens with the thing the firmware actually does, not a description
 * of it. Drag the phone and the measured distance, the tick count and the
 * verdict all move with it. Arm the relay and the measurement gets *longer*,
 * which is the whole argument for time-of-flight in one gesture: a relay can
 * add delay, and adding delay can only push you further away. There is no
 * attack that makes light arrive early.
 *
 * Every constant here is the firmware's own, cited to the line it lives on.
 * They are checked by tools/check_hero_constants.py, which re-reads each cited
 * line and fails the build if the value has moved.
 *
 * Progressive by construction: the SVG in the page is already a complete,
 * labelled, static round. This file adds interaction. With scripting off, or
 * before this file arrives, the hero is a diagram rather than a broken widget.
 *
 * The travelling pulses are CSS animations on transform, so they run on the
 * compositor and this file does no per-frame work at all. JavaScript only
 * runs when the reader moves something.
 */
(function () {
  "use strict";

  var svg = document.getElementById("hero-scope");
  var slider = document.getElementById("hs-range");
  if (!svg || !slider) return;

  /* ---- the firmware's numbers ------------------------------------------ */
  /* Same cited-constant format the twin uses, and checked the same way:
     `NAME: value, // path:line`. web/site/check_hero_constants.py re-reads
     each cited line from the C tree and fails if the value has moved off it.
     Keep the format; it is load-bearing, not decoration. */
  var FW = {
    UNLOCK_RANGE_CM: 100,     // apps/esp32-matter-lock/main/app_main.cpp:146
    CHIP_FREQ_HZ: 499200000,  // modules/ultrawidelock_dw3000/dwt_uwb_driver/deca_device_api.h:61
    TICKS_PER_CYCLE: 128,     // modules/ultrawidelock_dw3000/dwt_uwb_driver/deca_device_api.h:59
  };

  /* Speed of light in vacuum, SI exact. Not from the firmware -- it is not
     the firmware's to define. */
  var C_M_S = 299792458;

  /* One timestamp tick is 1/(499.2 MHz x 128) = 15.65 ps, which light crosses
     in 4.6917 mm. That number is the resolution of the whole product. */
  var TICK_S = 1 / (FW.CHIP_FREQ_HZ * FW.TICKS_PER_CYCLE);
  var MM_PER_TICK = TICK_S * C_M_S * 1000;
  var BOUND_M = FW.UNLOCK_RANGE_CM / 100;

  /* What a relay costs its operator. A repeater cannot subtract propagation
     time; it can only add its own. This is a deliberately modest figure --
     even a very fast relay lands outside a one-metre bound. */
  var RELAY_ADD_M = 1.20;

  /* ---- geometry -------------------------------------------------------- */
  /* The lock is the origin of the scale, because the lock is what the
     distance is measured from. The ruler in the SVG is drawn to these exact
     numbers: 0 m at x=84, 3 m at x=648, so 188 user units per metre and a
     tick every half metre. Change one and change the other. */
  var LOCK_X = 96, MAX_X = 888;
  var MIN_M = 0.10, MAX_M = 3.00;
  var PX_PER_M = (MAX_X - LOCK_X) / MAX_M;          /* 264 */
  var MIN_X = LOCK_X + MIN_M * PX_PER_M;            /* 122.4 */

  var el = {
    phone: document.getElementById("hs-phone"),
    rail: document.getElementById("hs-rail"),
    dim: document.getElementById("hs-dim"),
    dimTick: document.getElementById("hs-dim-tick"),
    dimCap: document.getElementById("hs-dim-cap"),
    relay: document.getElementById("hs-relay"),
    lanes: document.getElementById("hs-lanes"),
    laneLines: document.querySelectorAll(".hs-lane-line"),
    metres: document.getElementById("hs-m"),
    ticks: document.getElementById("hs-ticks"),
    nanos: document.getElementById("hs-ns"),
    truth: document.getElementById("hs-true"),
    verdict: document.getElementById("hs-verdict"),
    relayBtn: document.getElementById("hs-relay-btn"),
    scope: svg,
    phaseUwb: document.getElementById("hs-phase-uwb"),
    phaseGate: document.getElementById("hs-phase-gate"),
    phaseMatter: document.getElementById("hs-phase-matter")
  };

  var relayOn = false;

  /* ---- the grant ------------------------------------------------------- */
  /* Crossing inside the bound is the one event here worth marking, so it is
     the only thing that animates on demand. This function's entire job is a
     class on the block that encloses both the diagram and the readout; the
     stamp, the ring and the dimension flash are CSS on that class, so the
     crossing still costs no per-frame JavaScript.
     Seeded from the markup's own data-state, so the page does not celebrate
     its own first paint: an arrival has to be arrived at. */
  var band = svg.closest(".scope-in");
  var lastState = svg.getAttribute("data-state");

  function markState(state) {
    if (state === lastState) return;
    lastState = state;
    if (!band) return;
    band.classList.remove("granted");
    if (state !== "grant") return;
    /* Reading a layout value flushes the removal, so a second crossing
       restarts the animations instead of continuing the first. Once per
       crossing, never during one. */
    void band.offsetWidth;
    band.classList.add("granted");
  }

  function setPhase(node, state) {
    if (!node) return;
    node.classList.toggle("is-done", state === "done");
    node.classList.toggle("is-active", state === "active");
    node.classList.toggle("is-alert", state === "alert");
  }

  function drawPhases(state) {
    setPhase(el.phaseUwb, state === "grant" ? "done" : "active");
    setPhase(el.phaseGate, state === "grant" ? "done" :
      state === "relay" ? "alert" : "active");
    setPhase(el.phaseMatter, state === "grant" ? "active" : "idle");
  }

  function xToM(x) { return (x - LOCK_X) / PX_PER_M; }
  function mToX(m) { return LOCK_X + m * PX_PER_M; }
  function fmt(n, dp) { return n.toFixed(dp); }

  /* ---- render ---------------------------------------------------------- */
  function draw() {
    var trueM = xToM(+slider.value);
    var seenM = trueM + (relayOn ? RELAY_ADD_M : 0);
    var x = mToX(trueM);

    /* The phone and its rail sit at the true position. The dimension line
       spans the *measured* distance, so when the relay is armed you can see
       the measurement overshoot the phone. */
    el.phone.setAttribute("transform", "translate(" + x.toFixed(1) + ",0)");
    el.rail.setAttribute("transform", "translate(" + x.toFixed(1) + ",0)");

    var seenX = Math.min(mToX(seenM), MAX_X + 46);
    el.dim.setAttribute("x2", seenX.toFixed(1));
    el.dimTick.setAttribute("transform", "translate(" + seenX.toFixed(1) + ",0)");
    el.dimCap.setAttribute("x", ((LOCK_X + seenX) / 2).toFixed(1));
    el.dimCap.textContent = fmt(seenM, 2) + " m";

    /* Pulses travel the real gap, so the animation is the geometry. */
    el.lanes.style.setProperty("--travel", (x - LOCK_X).toFixed(1) + "px");
    /* The lanes end where the phone is. Drawn to a fixed width they implied
       the exchange continued past the device it was talking to. */
    for (var i = 0; i < el.laneLines.length; i++) {
      el.laneLines[i].setAttribute("x2", x.toFixed(1));
    }

    if (el.relay) {
      el.relay.style.display = relayOn ? "" : "none";
      if (relayOn) {
        var mid = (LOCK_X + x) / 2;
        el.relay.setAttribute("transform", "translate(" + mid.toFixed(1) + ",0)");
      }
    }

    var ticks = Math.round(seenM * 1000 / MM_PER_TICK);
    var ns = seenM / C_M_S * 1e9;

    el.metres.textContent = fmt(seenM, 2);
    el.ticks.textContent = ticks.toLocaleString("en");
    el.nanos.textContent = fmt(ns, 2);

    var granted = seenM <= BOUND_M;
    var state = relayOn ? "relay" : granted ? "grant" : "hold";
    el.scope.setAttribute("data-state", state);
    markState(state);
    drawPhases(state);

    if (relayOn) {
      el.verdict.textContent = "refused · added delay";
      el.truth.textContent = "phone is really at " + fmt(trueM, 2) +
        " m — the relay could only make that longer";
      el.truth.removeAttribute("hidden");
    } else {
      el.verdict.textContent = granted ? "unlock" : "held · out of range";
      el.truth.setAttribute("hidden", "");
    }

    slider.setAttribute("aria-valuetext",
      fmt(seenM, 2) + " metres measured, " + ticks + " ticks, " +
      (relayOn ? "refused, relay adds delay"
               : granted ? "inside the one metre bound, unlock"
                         : "outside the one metre bound, held"));
  }

  /* ---- drag ------------------------------------------------------------ */
  /* The slider is the real control: it carries the value, the keyboard
     support and the accessible name. Dragging the phone just writes to it,
     so there is exactly one source of truth and no state to keep in step. */
  function pointerToValue(evt) {
    var box = svg.getBoundingClientRect();
    var vb = svg.viewBox.baseVal;
    var x = (evt.clientX - box.left) / box.width * vb.width;
    return Math.max(MIN_X, Math.min(MAX_X, x));
  }

  var dragging = false;
  var target = document.getElementById("hs-hit") || svg;

  target.addEventListener("pointerdown", function (e) {
    dragging = true;
    target.setPointerCapture(e.pointerId);
    svg.classList.add("dragging");
    slider.value = pointerToValue(e);
    draw();
    e.preventDefault();
  });
  target.addEventListener("pointermove", function (e) {
    if (!dragging) return;
    slider.value = pointerToValue(e);
    draw();
  });
  function endDrag(e) {
    if (!dragging) return;
    dragging = false;
    svg.classList.remove("dragging");
    try { target.releasePointerCapture(e.pointerId); } catch (err) {}
  }
  target.addEventListener("pointerup", endDrag);
  target.addEventListener("pointercancel", endDrag);

  slider.addEventListener("input", draw);

  if (el.relayBtn) {
    el.relayBtn.addEventListener("click", function () {
      relayOn = !relayOn;
      el.relayBtn.setAttribute("aria-pressed", relayOn ? "true" : "false");
      el.relayBtn.textContent = relayOn ? "Relay armed" : "Arm a relay";
      el.relayBtn.classList.toggle("btn-warn", relayOn);
      draw();
    });
  }

  /* ---- first paint ----------------------------------------------------- */
  /* Start just inside the bound: the opening state should be the one the
     product is for, not an error condition. */
  slider.value = mToX(0.82);
  draw();
  svg.classList.add("live");

  /* ---- glass field ----------------------------------------------------- */
  /* Decorative ranging rings are active only while the hero is visible.
     The live SVG remains the semantic and interactive representation. */
  var canvas = document.getElementById("uwb-field");
  var hero = document.querySelector(".hero");
  var lock = svg.querySelector(".hs-lock");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var finePointer = window.matchMedia("(pointer: fine)").matches;
  var nav = document.querySelector(".topbar");

  function materializeNav() {
    if (nav) nav.classList.toggle("is-scrolled", window.scrollY > 24);
  }
  window.addEventListener("scroll", materializeNav, { passive: true });
  materializeNav();

  if (finePointer && !reduced) {
    var panels = document.querySelectorAll(".glass-panel, #main > .page, .cardgrid .card");
    var pointerX = 0, pointerY = 0, pointerQueued = false;
    window.addEventListener("pointermove", function (event) {
      pointerX = event.clientX;
      pointerY = event.clientY;
      if (pointerQueued) return;
      pointerQueued = true;
      window.requestAnimationFrame(function () {
        pointerQueued = false;
        for (var p = 0; p < panels.length; p++) {
          var rect = panels[p].getBoundingClientRect();
          if (rect.bottom < 0 || rect.top > window.innerHeight) continue;
          panels[p].style.setProperty("--gx",
            ((pointerX - rect.left) / rect.width * 100).toFixed(1) + "%");
          panels[p].style.setProperty("--gy",
            ((pointerY - rect.top) / rect.height * 100).toFixed(1) + "%");
        }
      });
    }, { passive: true });
  }

  if (canvas && hero && lock && !reduced) {
    var ctx = canvas.getContext("2d");
    var fieldW = 0, fieldH = 0, fieldDpr = 1;
    var fieldVisible = true, fieldFrame = 0, fieldLast = 0, fieldSpawn = 0;
    var rings = [], flashes = [];

    function fieldColour(alpha) {
      var value = window.getComputedStyle(document.documentElement)
        .getPropertyValue("--accent").trim();
      var match = /^#([0-9a-f]{6})$/i.exec(value);
      if (!match) return "rgba(46,230,184," + alpha + ")";
      var number = parseInt(match[1], 16);
      return "rgba(" + (number >> 16) + "," + ((number >> 8) & 255) + "," +
        (number & 255) + "," + alpha + ")";
    }

    function resizeField() {
      fieldDpr = Math.min(window.devicePixelRatio || 1, 1.75);
      fieldW = window.innerWidth;
      fieldH = window.innerHeight;
      canvas.width = Math.round(fieldW * fieldDpr);
      canvas.height = Math.round(fieldH * fieldDpr);
      canvas.style.width = fieldW + "px";
      canvas.style.height = fieldH + "px";
      ctx.setTransform(fieldDpr, 0, 0, fieldDpr, 0, 0);
    }

    function fieldOrigin() {
      var rect = lock.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    }

    function fieldLoop(now) {
      fieldFrame = 0;
      if (!fieldVisible || document.hidden) return;
      var dt = Math.min(34, now - (fieldLast || now));
      fieldLast = now;
      var origin = fieldOrigin();
      var maxRadius = Math.hypot(fieldW, fieldH) * .78;
      if (now - fieldSpawn > 1450) {
        rings.push({ radius: 28 });
        fieldSpawn = now;
      }
      ctx.clearRect(0, 0, fieldW, fieldH);
      rings = rings.filter(function (ring) {
        ring.radius += dt * .055;
        var alpha = Math.max(0, 1 - ring.radius / maxRadius) * .13;
        if (alpha < .004) return false;
        ctx.beginPath();
        ctx.arc(origin.x, origin.y, ring.radius, 0, Math.PI * 2);
        ctx.strokeStyle = fieldColour(alpha);
        ctx.lineWidth = 1;
        ctx.stroke();
        return true;
      });
      flashes = flashes.filter(function (flash) {
        flash.radius += dt * .42;
        flash.alpha *= Math.pow(.92, dt / 16.7);
        if (flash.alpha < .008) return false;
        ctx.beginPath();
        ctx.arc(origin.x, origin.y, flash.radius, 0, Math.PI * 2);
        ctx.strokeStyle = fieldColour(flash.alpha);
        ctx.lineWidth = 1.5;
        ctx.stroke();
        return true;
      });
      fieldFrame = window.requestAnimationFrame(fieldLoop);
    }

    function startField() {
      if (!fieldVisible || document.hidden || fieldFrame) return;
      fieldLast = 0;
      fieldFrame = window.requestAnimationFrame(fieldLoop);
    }

    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        fieldVisible = entries[0].isIntersecting;
        if (fieldVisible) startField();
      }, { rootMargin: "15% 0px" }).observe(hero);
    }
    document.addEventListener("visibilitychange", startField);
    window.addEventListener("resize", function () { resizeField(); startField(); });
    new MutationObserver(function () { startField(); })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    var oldMarkState = markState;
    markState = function (state) {
      var wasGrant = lastState === "grant";
      oldMarkState(state);
      if (state === "grant" && !wasGrant) flashes.push({ radius: 30, alpha: .48 });
    };

    resizeField();
    startField();
  }
})();
