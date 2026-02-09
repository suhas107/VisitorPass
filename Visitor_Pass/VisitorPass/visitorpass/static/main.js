document.addEventListener('DOMContentLoaded', () => {
  const manualForm = document.getElementById('manualVerify');
  if (manualForm) {
    manualForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const tokenInput = manualForm.querySelector('input[name="token"]');
      const resultBox = document.getElementById('result') || document.getElementById('manualResult');
      const resp = await fetch(manualForm.action, {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRFToken': manualForm.querySelector('input[name="csrf_token"]').value},
        body: JSON.stringify({token: tokenInput.value})
      });
      let data;
      try {
        data = await resp.json();
      } catch (err) {
        const text = await resp.text();
        data = {result: 'ERROR', notes: text};
      }
      let type = 'warning';
      if (data.result === 'VALID') type = 'success';
      else if (data.result === 'USED') type = 'warning';
      if (resultBox) {
        const details = data.details ? `<pre class="mb-2 small">${JSON.stringify(data.details, null, 2)}</pre>` : '';
        const retryBtn = `<button class="btn btn-outline-light btn-sm me-2 mt-2" type="button" onclick="window.location.reload()">Try again</button>`;
        const backBtn = `<a class="btn btn-secondary btn-sm mt-2" href="/dashboard">Back to dashboard</a>`;
        resultBox.innerHTML = `<div class="alert alert-${type}">${JSON.stringify(data)}<br>${details}${retryBtn}${backBtn}</div>`;
      } else {
        alert(JSON.stringify(data));
      }
    });
  }
});
