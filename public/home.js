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
  if (!rows.length) {
    $box.classList.add('hidden');
    $box.innerHTML = '';
    return;
  }

  $box.innerHTML = rows.map(r => {
    const isTopic = r.type === 'topic';
    const href    = isTopic
      ? `/topic/${encodeURIComponent(r.id)}`
      : `/questions/${encodeURIComponent(r.id)}`;
    const badge   = isTopic
      ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 text-sky-700 border border-sky-200">Ämne</span>'
      : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700 border border-violet-200">Fråga</span>';
    const snippet = r.snippet
      ? `<div class="text-xs text-slate-600 line-clamp-1">${escapeHtml(r.snippet)}</div>`
      : '';

    return `
      <a href="${href}" class="block px-4 py-3 hover:bg-slate-50">
        <div class="flex items-center gap-2">
          ${badge}
          <div class="font-medium text-slate-900 line-clamp-1">${escapeHtml(r.title || '')}</div>
        </div>
        ${snippet}
      </a>
    `;
  }).join('');

  $box.classList.remove('hidden');
}
  let tId = null;
  function debounce(fn, ms=150){ clearTimeout(tId); tId = setTimeout(fn, ms); }
let activeController = null;
let seq = 0;

async function fetchSuggest(q){
  if (!$box) return;
  try {
    if (!q) { renderSuggest([]); return; }

    // Avbryt ev. pågående request
    if (activeController) activeController.abort();
    const controller = new AbortController();
    activeController = controller;

    const mySeq = ++seq; // markera denna request
    const res = await fetch(`/api/suggest?q=${encodeURIComponent(q)}`, { signal: controller.signal });
    if (!res.ok) return;

    // Om ett annat (senare) svar redan kommit, ignorera detta
    if (mySeq !== seq) return;

    const data = await res.json();
    renderSuggest(Array.isArray(data) ? data : []);
  } catch (e) {
    // abort är ok, annars logga
    if (e.name !== 'AbortError') console.error(e);
  }
}
// --- results (bara på sidor som har #results) ---
async function searchAndRender(q) {
  // Finns ingen results-yta? Navigera till /search
  if (!$results) { goSearch(); return; }

  try {
    const url = q ? `/api/search?q=${encodeURIComponent(q)}` : `/api/search`;
    const res = await fetch(url, { headers: { 'Accept': 'application/json' }});
    if (!res.ok) { console.error('HTTP', res.status); return; }
    const rows = await res.json();

    $results.innerHTML = (rows || []).map(item => {
      const isTopic = item.type === 'topic';
      const href    = isTopic
        ? `/topic/${encodeURIComponent(item.id)}`
        : `/questions/${encodeURIComponent(item.id)}`;

      const badge   = isTopic
        ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 text-sky-700 border border-sky-200">Ämne</span>'
        : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700 border border-violet-200">Fråga</span>';

      const snippet = item.snippet
        ? `<p class="text-sm text-slate-600">${escapeHtml(item.snippet)}</p>`
        : '';

      return `
        <article class="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow transition">
          <div class="flex items-center gap-2 mb-2">${badge}</div>
          <h3 class="text-lg font-semibold text-slate-900 mb-1">
            <a href="${href}" class="hover:underline">
              ${escapeHtml(item.title || '')}
            </a>
          </h3>
          ${snippet}
        </article>
      `;
    }).join('');

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