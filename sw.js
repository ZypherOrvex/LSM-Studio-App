// LSM Studio v0.1.1 - funciona sin internet
var CACHE = 'lsm-studio-v0.1.1';
var FILES = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './icon-maskable-512.png'];
self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) {
    return Promise.all(FILES.map(function (f) { return c.add(f).catch(function () {}); }));
  }));
  self.skipWaiting();
});
self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (e) {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(function (r) {
      if (r && r.status === 200 && r.type === 'basic') {
        var copy = r.clone();
        caches.open(CACHE).then(function (c) { c.put(e.request, copy); });
      }
      return r;
    }).catch(function () {
      return caches.match(e.request, { ignoreSearch: true }).then(function (m) {
        return m || caches.match('./index.html') || caches.match('./');
      });
    })
  );
});
