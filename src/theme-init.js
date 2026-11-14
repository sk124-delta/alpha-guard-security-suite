// Runs before the page paints, so the saved theme applies without a flash of the wrong colors.
// Reads the same 'theme' key that app.js writes. Defaults to light.
(function () {
  var mode = 'light';
  try {
    if (localStorage.getItem('theme') === 'dark') mode = 'dark';
  } catch (e) {
    // Storage can be blocked (private mode, strict settings). Keep the light default.
  }
  document.documentElement.setAttribute('data-theme', mode);
})();