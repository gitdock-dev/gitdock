// Stagger: assign incremental delay to grid children
document.querySelectorAll('.pain-grid, .features-grid, .security-panel-grid, .steps').forEach(function (grid) {
  grid.querySelectorAll('.fade-in').forEach(function (child, i) {
    child.style.setProperty('--stagger', i * 0.09 + 's');
  });
});

// Intersection Observer for scroll-reveal animations
var observer = new IntersectionObserver(
  function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
        entry.target.addEventListener(
          'animationend',
          function () {
            this.classList.remove('fade-in', 'visible');
            this.style.removeProperty('--stagger');
          },
          { once: true }
        );
      }
    });
  },
  { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
);

document.querySelectorAll('.fade-in').forEach(function (el) {
  observer.observe(el);
});

// Spotlight: mouse-tracking glow on cards
(function () {
  var cards = document.querySelectorAll('.feat-card, .pain-card');
  if (!cards.length) return;
  cards.forEach(function (card) {
    card.addEventListener(
      'mousemove',
      function (e) {
        var rect = card.getBoundingClientRect();
        card.style.setProperty('--mx', e.clientX - rect.left + 'px');
        card.style.setProperty('--my', e.clientY - rect.top + 'px');
      },
      { passive: true }
    );
  });
})();
