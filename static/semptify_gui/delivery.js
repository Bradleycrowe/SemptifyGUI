document.addEventListener('DOMContentLoaded', async function () {
  const methodSelect = document.getElementById('method');
  const methodFields = document.getElementById('method-fields');
  const form = document.getElementById('delivery-form');
  const out = document.getElementById('delivery-result');

  async function loadMethods() {
    const res = await fetch('/semptify-gui/api/delivery/methods');
    const json = await res.json();
    return json.methods || [];
  }

  function renderFieldsFor(method) {
    methodFields.innerHTML = '';
    (method.requires || []).forEach(req => {
      const id = 'f_' + req;
      const label = document.createElement('label');
      label.textContent = req + ':';
      const input = document.createElement('input');
      input.name = req;
      input.id = id;
      input.type = 'text';
      methodFields.appendChild(label);
      methodFields.appendChild(document.createElement('br'));
      methodFields.appendChild(input);
      methodFields.appendChild(document.createElement('br'));
    });
  }

  const methods = await loadMethods();
  methods.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.name;
    methodSelect.appendChild(opt);
  });

  if (methods.length) renderFieldsFor(methods[0]);

  methodSelect.addEventListener('change', function () {
    const m = methods.find(x => x.id === this.value);
    renderFieldsFor(m || {});
  });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    out.textContent = 'Sending...';
    const method = methodSelect.value;
    const inputs = methodFields.querySelectorAll('input');
    const details = {};
    inputs.forEach(i => { details[i.name] = i.value; });

    try {
      const res = await fetch('/semptify-gui/api/delivery', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, details }),
      });
      const d = await res.json();
      out.textContent = JSON.stringify(d, null, 2);
    } catch (err) {
      out.textContent = 'Error: ' + err;
    }
  });
});
