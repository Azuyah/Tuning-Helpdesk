document.addEventListener('DOMContentLoaded', () => {
  const $q       = document.getElementById('q');
  const $btn     = document.getElementById('btnSearch');
  const $box     = document.getElementById('suggestBox'); // kan saknas
  const $results = document.getElementById('results');    // kan saknas

  if (!$q || !$btn) {

    return;
  }

  // ---- helper: navigera till söksida ----
  function goSearch() {
    const q = ($q.value || '').trim();
    const url = q ? '/search?q=' + encodeURIComponent(q) : '/search';
    window.location.href = url;
  }

  // ---- state för autosuggest (för att hindra out-of-order) ----
  let suggestController = null;
  let reqSeq = 0;          // ökar för varje request
  let lastRenderedSeq = 0; // senaste seq som faktiskt renderades

  // ---- rendera autosuggest ----
  function renderSuggest(rows = [], seq = 0) {
    if (seq < lastRenderedSeq) {
      return; // äldre svar: ignorera
    }
    lastRenderedSeq = seq;

    if (!$box) return;
    if (!rows.length) {
      $box.classList.add('hidden');
      $box.innerHTML = '';
      return;
    }

    $box.innerHTML = rows.map(r => {
      // Rätt länk per typ
      const href =
        r.type === 'resource' ? `/resources/${encodeURIComponent(r.id)}` :
        r.type === 'question' ? `/questions/${encodeURIComponent(r.id)}` :
                                `/topic/${encodeURIComponent(r.id)}`;

      // Badge per typ
      const badge =
        r.type === 'question'
          ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700 border border-violet-200">Fråga</span>'
          : (r.type === 'resource'
              ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 border border-amber-200">Resurs</span>'
              : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 text-sky-700 border border-sky-200">Ämne</span>');

      const snippet = r.snippet
        ? `<div class="text-xs text-slate-600 line-clamp-1">${escapeHtml(r.snippet)}</div>`
        : '';

      return `
        <a href="${href}" class="block px-4 py-3 hover:bg-slate-50" data-type="${r.type}" data-id="${encodeURIComponent(r.id)}">
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

  // ---- debounce helper ----
  let debounceId = null;
  function debounce(fn, ms = 150) {
    return function(...args) {
      clearTimeout(debounceId);
      debounceId = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  // ---- hämta autosuggest ----
  const fetchSuggest = async (q) => {
    if (!q) { renderSuggest([], ++reqSeq); return; }

    // Avbryt ev. pågående request
    if (suggestController) {
      suggestController.abort();
    }
    suggestController = new AbortController();

    const mySeq = ++reqSeq;

    try {
      const res = await fetch('/api/suggest?q=' + encodeURIComponent(q), { signal: suggestController.signal });
      if (!res.ok) {
        return;
      }
      const data = await res.json();

      // Rendera endast om seq är färskast (sköts i renderSuggest)
      renderSuggest(Array.isArray(data) ? data : [], mySeq);
    } catch (e) {
      if (e.name === 'AbortError') {
      } else {
      }
    }
  };

  // ---- results (endast sidor med #results) ----
  async function searchAndRender(q) {
    if (!$results) { goSearch(); return; }
    try {
      const url = q ? '/api/search?q=' + encodeURIComponent(q) : '/api/search';
      const res = await fetch(url, { headers: { 'Accept': 'application/json' }});
      const rows = await res.json();

      $results.innerHTML = (rows || []).map(item => {
        const href =
          item.type === 'question' ? `/questions/${encodeURIComponent(item.id)}` :
          item.type === 'resource' ? `/resources/${encodeURIComponent(item.id)}` :
                                     `/topic/${encodeURIComponent(item.id)}`;

        const badge =
          item.type === 'question'
            ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 text-violet-700 border border-violet-200">Fråga</span>'
            : (item.type === 'resource'
                ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 text-amber-700 border border-amber-200">Resurs</span>'
                : '<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 text-sky-700 border border-sky-200">Ämne</span>');

        const snippet = item.snippet
          ? `<p class="text-sm text-slate-600">${escapeHtml(item.snippet)}</p>`
          : '';

        return `
          <article class="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm hover:shadow transition">
            <div class="flex items-center gap-2 mb-2">${badge}</div>
            <h3 class="text-lg font-semibold text-slate-900 mb-1">
              <a href="${href}" class="hover:underline">${escapeHtml(item.title || '')}</a>
            </h3>
            ${snippet}
          </article>
        `;
      }).join('');
    } catch (e) {
    }
  }

  // ---- utils ----
  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  // ---- events ----
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
    if (e.key === 'Escape') {
      $box && $box.classList.add('hidden');
    }
  });

  $q.addEventListener('input', debounce(() => {
    const term = $q.value.trim();
    fetchSuggest(term);
  }, 150));

  document.addEventListener('click', (e) => {
    if ($box && !e.target.closest('#suggestBox') && e.target !== $q) {
      $box.classList.add('hidden');
    }
  });

  // Populära taggar
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.tag-btn');
    if (!btn) return;
    const tag = btn.getAttribute('data-tag') || '';
    $q.value = tag;
    $results ? searchAndRender(tag) : goSearch();
  });

  // Init på sidor med #results
  const urlQ = new URLSearchParams(location.search).get('q') || '';
  if (urlQ) $q.value = urlQ;
  if ($results) searchAndRender(urlQ);
});