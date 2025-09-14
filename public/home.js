document.addEventListener('DOMContentLoaded', () => {
  const $q   = document.getElementById('q');
  const $btn = document.getElementById('btnSearch');
  const $box = document.getElementById('suggestBox');   // kan saknas
  const $results = document.getElementById('results');   // kan saknas

  if (!$q || !$btn) return; // finns ingen sökruta → gör inget

  // --- gemensam: gå till resultatsida ---
  function goSearch() {
    const q = ($q.value || '').trim();
    const url = q ? `/search?q=${encodeURIComponent(q)}` : '/search';
    window.location.href = url;
  }

  // --- autosuggest (om suggestBox finns) ---
  function renderSuggest(rows = []) {
    if (!$box) return;
    if (!rows.length) { $box.classList.add('hidden'); $box.innerHTML = ''; return; }
    $box.innerHTML = rows.map(r => `
      <a href="/topic/${encodeURIComponent(r.id)}" class="block px-4 py-3 hover:bg-slate-50">
        <div class="font-medium text-slate-900 line-clamp-1">${escapeHtml(r.title||'')}</div>
        ${r.snippet ? `<div class="text-sm text-slate-600 line-clamp-1">${escapeHtml(r.snippet)}</div>` : ''}
      </a>
    `).join('');
    $box.classList.remove('hidden');
  }

  let tId = null;
  function debounce(fn, ms=150){ clearTimeout(tId); tId = setTimeout(fn, ms); }

  async function fetchSuggest(q){
    if (!$box) return;
    try {
      if (!q) { renderSuggest([]); return; }
      const res = await fetch(`/api/suggest?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      renderSuggest(Array.isArray(data) ? data : []);
    } catch(e) { console.error(e); }
  }

  // --- results (bara på sidor som har #results) ---
  async function searchAndRender(q) {
    // Finns ingen results-yta? Navigera till /search
    if (!$results) { goSearch(); return; }

    try {
      const url = q ? `/api/search?q=${encodeURIComponent(q)}` : '/api/search';
      const res = await fetch(url, { headers: { 'Accept': 'application/json' }});
      if (!res.ok) { console.error('HTTP', res.status); return; }
      const rows = await res.json();
      $results.innerHTML = (rows || []).map(t => `
        <article class="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow transition">
          <h3 class="text-lg font-semibold text-slate-900 mb-1">
            <a href="/topic/${encodeURIComponent(t.id)}" class="hover:underline">
              ${escapeHtml(t.title || '')}
            </a>
          </h3>
          ${t.excerpt ? `<p class="text-sm text-slate-600">${escapeHtml(t.excerpt)}</p>` : ``}
        </article>
      `).join('');
    } catch (e) {
      console.error('Search error', e);
    }
  }

  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  // --- events ---
  $btn.addEventListener('click', () => {
    const q = $q.value.trim();
    $results ? searchAndRender(q) : goSearch();
  });

  $q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const q = $q.value.trim();
      $results ? searchAndRender(q) : goSearch();
    }
  });

  // autosuggest (om box finns)
  $q.addEventListener('input', () => debounce(() => fetchSuggest($q.value.trim()), 150));
  document.addEventListener('click', (e) => {
    if ($box && !e.target.closest('#suggestBox') && e.target !== $q) $box.classList.add('hidden');
  });

  // populära knappar
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.tag-btn');
    if (!btn) return;
    const tag = btn.getAttribute('data-tag') || '';
    $q.value = tag;
    $results ? searchAndRender(tag) : goSearch();
  });

  // initial (bara om #results finns → t.ex. på /search)
  const urlQ = new URLSearchParams(location.search).get('q') || '';
  if (urlQ) $q.value = urlQ;
  if ($results) searchAndRender(urlQ);
});