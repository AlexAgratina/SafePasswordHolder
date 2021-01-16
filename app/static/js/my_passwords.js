document.addEventListener('DOMContentLoaded', () => {
    const shareList = document.getElementById('share-list');
    const publicToggle = document.getElementById('public-toggle');
    const globalBadge = document.getElementById('global-badge');

    publicToggle.addEventListener('change', (e) => {
        const global = e.target.checked;

        shareList.disabled = global;
        globalBadge.style.display = global ? '' : 'none';
    });
});