(function () {
  function rewrite(u) {
    return u
      .replace('https://identitytoolkit.googleapis.com/v1', 'http://localhost:8080/__fbauth/v1')
      .replace('https://securetoken.googleapis.com/v1', 'http://localhost:8080/__fbauth/v1');
  }
  function isFb(url) {
    return typeof url === 'string' &&
      /^(https:\/\/)?(identitytoolkit|securetoken)\.googleapis\.com\//.test(url);
  }
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      if (isFb(input)) input = rewrite(input);
      return origFetch.call(this, input, init);
    };
  }
  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (isFb(url)) url = rewrite(url);
    return origOpen.apply(this, arguments);
  };
})();
