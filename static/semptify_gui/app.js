document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('complaint-form');
  const out = document.getElementById('complaint-result');

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const name = document.getElementById('name').value;
    const issue = document.getElementById('issue').value;
    out.textContent = 'Sending...';
    try {
      const res = await fetch('/semptify-gui/api/complaint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, issue }),
      });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      out.textContent = 'Error: ' + err;
    }
  });
});
