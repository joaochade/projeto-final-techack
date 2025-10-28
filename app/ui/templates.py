def home_html():
    return """
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8" />
<title>Detector de Phishing (MVP)</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:900px}
.card{border:1px solid #ddd;border-radius:14px;padding:18px;margin-top:20px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600}
.badge.seguro{background:#e6ffed}
.badge.suspeito{background:#fff8e6}
.badge.malicioso{background:#ffe6e6}
table{width:100%;border-collapse:collapse;margin-top:10px}
td,th{border-bottom:1px solid #eee;padding:8px;text-align:left}
input[type=text]{width:70%;padding:10px;border:1px solid #ddd;border-radius:10px}
button{padding:10px 16px;border:0;border-radius:10px;background:#111;color:#fff;cursor:pointer}
</style>
</head>
<body>
<h1>Detector de Phishing — MVP</h1>
<form id="form">
  <input type="text" name="url" placeholder="https://exemplo.com/login" />
  <button>Verificar</button>
</form>
<div id="result"></div>
<script>
const form = document.getElementById('form');
const result = document.getElementById('result');
form.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const url = new FormData(form).get('url');
  result.innerHTML = '<div class="card">Analisando...</div>';
  const r = await fetch('/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
  const data = await r.json();
  const cls = data.label === 'Seguro' ? 'seguro' : (data.label==='Suspeito'?'suspeito':'malicioso');
  result.innerHTML = `
    <div class="card">
      <div class="badge ${cls}">${data.label} — score ${data.score}</div>
      <p><b>URL normalizada:</b> ${data.normalized_url}</p>
      <table>
        <tbody>
          ${Object.entries(data.features).map(([k,v])=>`<tr><th>${k}</th><td>${v}</td></tr>`).join('')}
        </tbody>
      </table>
      <p><b>Evidências:</b> ${data.evidence.length? data.evidence.join(' • '): 'Nenhuma forte'}</p>
    </div>`;
});
</script>
</body>
</html>
"""