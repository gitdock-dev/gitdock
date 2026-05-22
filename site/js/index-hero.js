(function () {
  'use strict';

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  var canvas = document.getElementById('hero-canvas');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  var dpr = Math.min(window.devicePixelRatio || 1, 2);

  var BLUE = { r: 88, g: 166, b: 255 };
  var PURPLE = { r: 188, g: 140, b: 255 };
  var CYAN = { r: 57, g: 197, b: 207 };
  var COLORS = [BLUE, BLUE, BLUE, PURPLE, PURPLE, CYAN];

  var isMobile = window.innerWidth < 768;
  var PARTICLE_COUNT = isMobile ? 35 : 80;
  var MAX_DIST = isMobile ? 110 : 150;
  var MAX_DIST_SQ = MAX_DIST * MAX_DIST;
  var BASE_SPEED = 0.15;
  var MOUSE_RADIUS = isMobile ? 0 : 200;
  var MOUSE_RADIUS_SQ = MOUSE_RADIUS * MOUSE_RADIUS;
  var MOUSE_FORCE = 0.02;
  var CONN_OPACITY = 0.15;
  var FADE_ZONE = 150;

  var width = 0,
    height = 0;
  var particles = [];
  var mouseX = -9999,
    mouseY = -9999;
  var animId = 0;
  var running = true;
  var bottomFade = null;

  function resize() {
    var rect = canvas.parentElement.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    bottomFade = ctx.createLinearGradient(0, height - FADE_ZONE, 0, height);
    bottomFade.addColorStop(0, 'rgba(13,17,23,0)');
    bottomFade.addColorStop(1, 'rgba(13,17,23,1)');
  }

  function makeParticle() {
    var c = COLORS[(Math.random() * COLORS.length) | 0];
    return {
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * BASE_SPEED * 2,
      vy: (Math.random() - 0.5) * BASE_SPEED * 2,
      r: 1 + Math.random() * 1.5,
      cr: c.r,
      cg: c.g,
      cb: c.b,
      bo: 0.35 + Math.random() * 0.45,
      ph: Math.random() * 6.2832,
      ps: 0.004 + Math.random() * 0.008,
      o: 0
    };
  }

  function init() {
    resize();
    particles = [];
    for (var i = 0; i < PARTICLE_COUNT; i++) particles.push(makeParticle());
  }

  function tick() {
    if (!running) return;

    ctx.clearRect(0, 0, width, height);

    var i, j, p, q, dx, dy, dSq, d, f, op;
    var maxV = BASE_SPEED * 3;

    for (i = 0; i < particles.length; i++) {
      p = particles[i];

      if (MOUSE_RADIUS > 0) {
        dx = p.x - mouseX;
        dy = p.y - mouseY;
        dSq = dx * dx + dy * dy;
        if (dSq < MOUSE_RADIUS_SQ && dSq > 1) {
          d = Math.sqrt(dSq);
          f = (1 - d / MOUSE_RADIUS) * MOUSE_FORCE;
          p.vx += (dx / d) * f;
          p.vy += (dy / d) * f;
        }
      }

      p.vx *= 0.994;
      p.vy *= 0.994;

      if (p.vx > maxV) p.vx = maxV;
      else if (p.vx < -maxV) p.vx = -maxV;
      if (p.vy > maxV) p.vy = maxV;
      else if (p.vy < -maxV) p.vy = -maxV;

      p.x += p.vx;
      p.y += p.vy;

      if (p.x < -50) p.x += width + 100;
      else if (p.x > width + 50) p.x -= width + 100;
      if (p.y < -50) p.y += height + 100;
      else if (p.y > height + 50) p.y -= height + 100;

      p.ph += p.ps;
      p.o = p.bo * (0.65 + 0.35 * Math.sin(p.ph));
    }

    ctx.lineWidth = 0.6;
    for (i = 0; i < particles.length; i++) {
      p = particles[i];
      for (j = i + 1; j < particles.length; j++) {
        q = particles[j];
        dx = p.x - q.x;
        dy = p.y - q.y;
        dSq = dx * dx + dy * dy;

        if (dSq < MAX_DIST_SQ) {
          d = Math.sqrt(dSq);
          op = (1 - d / MAX_DIST) * CONN_OPACITY;

          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.strokeStyle =
            'rgba(' +
            ((p.cr + q.cr) >> 1) +
            ',' +
            ((p.cg + q.cg) >> 1) +
            ',' +
            ((p.cb + q.cb) >> 1) +
            ',' +
            op +
            ')';
          ctx.stroke();
        }
      }
    }

    for (i = 0; i < particles.length; i++) {
      p = particles[i];

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r * 4, 0, 6.2832);
      ctx.fillStyle = 'rgba(' + p.cr + ',' + p.cg + ',' + p.cb + ',' + p.o * 0.07 + ')';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, 6.2832);
      ctx.fillStyle = 'rgba(' + p.cr + ',' + p.cg + ',' + p.cb + ',' + p.o + ')';
      ctx.fill();
    }

    if (bottomFade) {
      ctx.fillStyle = bottomFade;
      ctx.fillRect(0, height - FADE_ZONE, width, FADE_ZONE);
    }

    animId = requestAnimationFrame(tick);
  }

  var hero = canvas.parentElement;
  var mThrottle = false;
  hero.addEventListener(
    'mousemove',
    function (e) {
      if (mThrottle) return;
      mThrottle = true;
      var rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
      requestAnimationFrame(function () {
        mThrottle = false;
      });
    },
    { passive: true }
  );

  hero.addEventListener(
    'mouseleave',
    function () {
      mouseX = -9999;
      mouseY = -9999;
    },
    { passive: true }
  );

  var resizeTimer;
  window.addEventListener(
    'resize',
    function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        var nowMobile = window.innerWidth < 768;
        if (nowMobile && particles.length > 35) particles.length = 35;
        resize();
      }, 250);
    },
    { passive: true }
  );

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      running = false;
      cancelAnimationFrame(animId);
    } else {
      running = true;
      animId = requestAnimationFrame(tick);
    }
  });

  init();
  tick();
})();
