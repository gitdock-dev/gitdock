// Stagger: assign incremental delay to grid children
document.querySelectorAll('.pain-grid, .features-grid, .security-panel-grid, .steps').forEach(function (grid) {
  grid.querySelectorAll('.fade-in').forEach(function (child, i) {
    child.style.setProperty('--stagger', i * 0.06 + 's');
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
  { threshold: 0.08, rootMargin: '0px 0px -32px 0px' }
);

document.querySelectorAll('.fade-in').forEach(function (el) {
  observer.observe(el);
});
