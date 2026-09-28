// Keep the whole left nav on screen when the footer scrolls into view.
//
// Mintlify's sidebar is sticky and as tall as the viewport, so the footer
// pushes it up and hides its first items. While the footer is visible, this
// shortens the sidebar to end at the footer's top edge; otherwise it leaves
// Mintlify's own height in place. `#sidebar` and `#footer` are Mintlify's ids.
(function () {
  var pending = false;

  function fit() {
    pending = false;
    var nav = document.getElementById('sidebar');
    var footer = document.getElementById('footer');
    if (!nav || !footer) return;
    var footerTop = footer.getBoundingClientRect().top;
    if (footerTop >= window.innerHeight) {
      nav.style.height = '';
      return;
    }
    var navTop = parseFloat(getComputedStyle(nav).top) || 0;
    nav.style.height = Math.max(footerTop - navTop, 0) + 'px';
  }

  function schedule() {
    if (pending) return;
    pending = true;
    window.requestAnimationFrame(fit);
  }

  window.addEventListener('scroll', schedule, { passive: true });
  window.addEventListener('resize', schedule);
  // Client-side navigation swaps the page without a scroll event.
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
  schedule();
})();
