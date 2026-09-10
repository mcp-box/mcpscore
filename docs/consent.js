// Analytics consent for docs.mcpscore.dev.
//
// Mintlify loads every .js file in this directory on every page, after the
// page is interactive. docs.json's `integrations.cookies` makes Mintlify hold
// its telemetry — Google Analytics included — until localStorage carries
// `mcpscore.analytics-consent=granted`, the exact key and value the banner on
// mcpscore.dev writes (mcpscore-web/src/lib/analytics.ts). localStorage is
// per origin, so this script does two things the site's banner cannot:
//
// 1. Adopt a choice made on mcpscore.dev. Both banners write a
//    `mcpscore.analytics-consent` cookie on the shared parent domain on every
//    choice, so the cookie always carries the newest one and is authoritative
//    over this origin's localStorage (which can hold a grant the visitor has
//    since withdrawn on the site). A visitor who already chose there is not
//    asked again here. Mintlify read localStorage before this script ran, so
//    a synced grant takes effect on the next full page load; that first page
//    view goes unmeasured on purpose rather than reloading a page the visitor
//    did not ask to reload. A synced withdrawal that finds a stale grant here
//    does reload, so the tag that stale value let Mintlify start stops now.
//    A choice stored here before the cookie existed is copied into it, so
//    the site learns it too.
// 2. Ask, with the same words as the site, when no choice exists anywhere.
//    Accept stores the choice in both places and reloads once so Mintlify
//    picks it up; Decline stores it and shows nothing more.
//
// Nothing here loads a script or sends a request; what the terms at
// https://mcpscore.dev/terms promise for the site holds for the docs.
(function () {
  var KEY = 'mcpscore.analytics-consent';
  var MAX_AGE = 60 * 60 * 24 * 365;
  var TERMS_URL = 'https://mcpscore.dev/terms';

  function readStorage() {
    try {
      var value = window.localStorage.getItem(KEY);
      return value === 'granted' || value === 'denied' ? value : null;
    } catch (error) {
      return null;
    }
  }

  function readCookie() {
    var match = document.cookie.match(
      /(?:^|;\s*)mcpscore\.analytics-consent=(granted|denied)(?:;|$)/
    );
    return match ? match[1] : null;
  }

  function cookieDomain() {
    var host = window.location.hostname;
    if (host === 'mcpscore.dev' || host.slice(-13) === '.mcpscore.dev') {
      return '; Domain=mcpscore.dev';
    }
    return '';
  }

  function store(choice) {
    try {
      window.localStorage.setItem(KEY, choice);
    } catch (error) {
      // Storage blocked: the choice still governs this page view.
    }
    document.cookie =
      KEY + '=' + choice + '; Max-Age=' + MAX_AGE + '; Path=/; SameSite=Lax' +
      (window.location.protocol === 'https:' ? '; Secure' : '') +
      cookieDomain();
  }

  var stored = readStorage();
  var fromSite = readCookie();
  if (fromSite !== null) {
    store(fromSite);
    if (stored === 'granted' && fromSite === 'denied') {
      window.location.reload();
    }
    return;
  }
  if (stored !== null) {
    store(stored);
    return;
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  var banner = element('section', 'mcpscore-consent');
  banner.setAttribute('role', 'region');
  banner.setAttribute('aria-label', 'Analytics consent');

  var inner = element('div', 'mcpscore-consent__inner');
  var copy = element('p', 'mcpscore-consent__copy');
  copy.appendChild(
    document.createTextNode(
      'We use Google Analytics to see which pages people find useful. Nothing ' +
        'loads until you choose. The docs work either way — see our '
    )
  );
  var link = element('a', 'mcpscore-consent__link', 'Terms & Privacy');
  link.href = TERMS_URL;
  copy.appendChild(link);
  copy.appendChild(document.createTextNode('.'));

  var actions = element('div', 'mcpscore-consent__actions');
  var decline = element('button', 'mcpscore-consent__button', 'Decline');
  decline.type = 'button';
  var accept = element(
    'button',
    'mcpscore-consent__button mcpscore-consent__button--primary',
    'Accept'
  );
  accept.type = 'button';

  decline.addEventListener('click', function () {
    store('denied');
    banner.remove();
  });
  accept.addEventListener('click', function () {
    store('granted');
    banner.remove();
    // Mintlify checked localStorage before this script ran; a reload is what
    // turns the tag on, and the visitor just asked for exactly that.
    window.location.reload();
  });

  actions.appendChild(decline);
  actions.appendChild(accept);
  inner.appendChild(copy);
  inner.appendChild(actions);
  banner.appendChild(inner);
  document.body.appendChild(banner);
})();
