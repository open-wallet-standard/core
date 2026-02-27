// === Docs config ===
var DOCS = [
  { slug: '01-storage-format',           num: '01', title: '01 \u2014 Storage Format',           sidebar: '01 \u2014 Storage Format' },
  { slug: '02-chain-agnostic-addressing', num: '02', title: '02 \u2014 Chain-Agnostic Addressing', sidebar: '02 \u2014 Addressing' },
  { slug: '03-signing-interface',         num: '03', title: '03 \u2014 Signing Interface',         sidebar: '03 \u2014 Signing Interface' },
  { slug: '04-policy-engine',             num: '04', title: '04 \u2014 Policy Engine',             sidebar: '04 \u2014 Policy Engine' },
  { slug: '05-key-isolation',             num: '05', title: '05 \u2014 Key Isolation',             sidebar: '05 \u2014 Key Isolation' },
  { slug: '06-agent-access-layer',        num: '06', title: '06 \u2014 Agent Access Layer',        sidebar: '06 \u2014 Agent Access' },
  { slug: '07-multi-chain-support',       num: '07', title: '07 \u2014 Multi-Chain Support',       sidebar: '07 \u2014 Multi-Chain' },
  { slug: '08-wallet-lifecycle',          num: '08', title: '08 \u2014 Wallet Lifecycle',          sidebar: '08 \u2014 Wallet Lifecycle' },
];

// Vercel build copies docs into website/docs/md/; local dev serves from repo root
var DOCS_PATHS = ['md', '../../docs'];
var isFirstBlockquote = true;

// === Marked renderer (v15 token-object API) ===
marked.use({
  renderer: {
    blockquote: function (token) {
      if (isFirstBlockquote) {
        isFirstBlockquote = false;
        // body is already-parsed HTML; strip wrapping <p> tags for subtitle
        var inner = token.body.replace(/^<p>/, '').replace(/<\/p>\n?$/, '');
        return '<p class="subtitle">' + inner + '</p>\n';
      }
      return '<blockquote>' + token.body + '</blockquote>\n';
    },

    heading: function (token) {
      var id = token.text.toLowerCase()
        .replace(/<[^>]+>/g, '')
        .replace(/[^\w]+/g, '-')
        .replace(/(^-|-$)/g, '');
      return '<h' + token.depth + ' id="' + id + '">' + token.text + '</h' + token.depth + '>\n';
    },

    code: function (token) {
      var lang = (token.lang || '').trim();
      if (lang && hljs.getLanguage(lang)) {
        var highlighted = hljs.highlight(token.text, { language: lang }).value;
        return '<pre><code class="hljs language-' + lang + '">' + highlighted + '</code></pre>\n';
      }
      // No language or unknown — render plain (preserves directory trees, ASCII diagrams)
      var escaped = token.text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      return '<pre><code>' + escaped + '</code></pre>\n';
    },
  },
});

// === Build sidebar ===
function buildSidebar(currentSlug) {
  var sidebar = document.getElementById('docs-sidebar');
  if (!sidebar) return;

  var html = '<div class="docs-sidebar-title">Specification</div>';
  html += '<a href="./">Overview</a>';
  DOCS.forEach(function (doc) {
    var active = doc.slug === currentSlug ? ' class="active"' : '';
    html += '<a href="doc.html?slug=' + doc.slug + '"' + active + '>' + doc.sidebar + '</a>';
  });
  sidebar.innerHTML = html;
}

// === Build prev / next nav ===
function buildNav(currentSlug) {
  var idx = DOCS.findIndex(function (d) { return d.slug === currentSlug; });
  if (idx === -1) return '';

  var html = '<div class="docs-nav">';

  if (idx === 0) {
    html += '<a href="./"><span class="label">Previous</span><span class="title">\u2190 Overview</span></a>';
  } else {
    var prev = DOCS[idx - 1];
    html += '<a href="doc.html?slug=' + prev.slug + '"><span class="label">Previous</span><span class="title">\u2190 ' + prev.title + '</span></a>';
  }

  if (idx < DOCS.length - 1) {
    var next = DOCS[idx + 1];
    html += '<a href="doc.html?slug=' + next.slug + '" class="next"><span class="label">Next</span><span class="title">' + next.title + ' \u2192</span></a>';
  } else {
    html += '<div></div>';
  }

  html += '</div>';
  return html;
}

// === Copy buttons on pre blocks ===
function addCopyButtons() {
  document.querySelectorAll('.docs-content pre').forEach(function (pre) {
    var wrapper = document.createElement('div');
    wrapper.style.position = 'relative';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);

    var btn = document.createElement('button');
    btn.className = 'code-copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(pre.textContent).then(function () {
        btn.textContent = 'Copied!';
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      });
    });
    wrapper.appendChild(btn);
  });
}

// === Hash scroll ===
function scrollToHash() {
  if (window.location.hash) {
    var el = document.querySelector(window.location.hash);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// === Main ===
async function loadDoc() {
  var params = new URLSearchParams(window.location.search);
  var slug = params.get('slug');
  if (!slug) { window.location.href = './'; return; }

  var doc = DOCS.find(function (d) { return d.slug === slug; });
  if (!doc) { window.location.href = './'; return; }

  document.title = doc.title + ' - LWS Docs';
  buildSidebar(slug);

  var content = document.getElementById('docs-content');

  try {
    var md;
    for (var i = 0; i < DOCS_PATHS.length; i++) {
      var res = await fetch(DOCS_PATHS[i] + '/' + slug + '.md');
      if (res.ok) { md = await res.text(); break; }
    }
    if (!md) throw new Error('not found');

    isFirstBlockquote = true;
    content.innerHTML = marked.parse(md) + buildNav(slug);
    addCopyButtons();
    scrollToHash();
  } catch (e) {
    content.innerHTML = '<h1>Not Found</h1><p>Could not load <code>' + slug + '.md</code>.</p>';
  }
}

window.addEventListener('hashchange', scrollToHash);
loadDoc();
