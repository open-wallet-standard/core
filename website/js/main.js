// Copy code block contents
function copyCode(button) {
  const wrapper = button.closest('.code-block-wrapper');
  const code = wrapper.querySelector('pre').textContent;
  navigator.clipboard.writeText(code).then(() => {
    const original = button.textContent;
    button.textContent = 'Copied!';
    setTimeout(() => { button.textContent = original; }, 2000);
  });
}

// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// Active nav link highlighting on scroll
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.header-nav a[href^="#"]');

function updateActiveNav() {
  const scrollPos = window.scrollY + 100;
  sections.forEach(section => {
    const top = section.offsetTop;
    const height = section.offsetHeight;
    const id = section.getAttribute('id');
    if (scrollPos >= top && scrollPos < top + height) {
      navLinks.forEach(link => {
        link.style.color = '';
        if (link.getAttribute('href') === '#' + id) {
          link.style.color = 'var(--black)';
        }
      });
    }
  });
}

window.addEventListener('scroll', updateActiveNav);
updateActiveNav();

// Docs sidebar active state
const sidebarLinks = document.querySelectorAll('.docs-sidebar a');
sidebarLinks.forEach(link => {
  if (link.href === window.location.href) {
    link.classList.add('active');
  }
});
