// Highlight the current page the user is on in the nav bar
// Wait for whole event page to be loaded
addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.nav-link').forEach(
        link => {
            // Add the selector when to current page
            if (link.href === window.location.href) {
                link.setAttribute('aria-current', 'page');
                link.classList.add('active');
            }
        }
    )
})