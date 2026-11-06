(function () {
  var f = document.getElementById('f'), msg = document.getElementById('msg'), go = document.getElementById('go');
  var box = document.getElementById('totpbox');
  if (box.dataset.totp === '1') box.hidden = false;
  f.addEventListener('submit', function (e) {
    e.preventDefault();
    go.disabled = true; msg.className = ''; msg.textContent = '';
    var body = { password: document.getElementById('pw').value };
    var t = document.getElementById('totp').value.trim();
    if (t) body.totp = t;
    fetch('/admin/api/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) { return r.json().catch(function () { return { ok: false, error: 'Unexpected response' }; }); })
      .then(function (j) {
        if (j.ok) { location.href = '/admin'; return; }
        msg.className = 'bad';
        msg.textContent = j.code === 'locked'
          ? 'Too many attempts. Try again in ' + Math.ceil((j.retry_after || 60) / 60) + ' min.'
          : (j.error || 'Login failed');
        document.getElementById('pw').value = '';
      })
      .catch(function () { msg.className = 'bad'; msg.textContent = 'Network error'; })
      .then(function () { go.disabled = false; });
  });
})();
