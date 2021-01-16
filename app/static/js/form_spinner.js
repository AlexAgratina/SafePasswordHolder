const addSpinner = () => {
    if (document.getElementById('loading-spinner'))
        return;

    const targetElement = document.getElementById('submit-button');
    const spinner = document.createElement('i');
    spinner.classList.add('fas');
    spinner.classList.add('fa-spinner');
    spinner.classList.add('ml-1')
    spinner.id = 'loading-spinner';

    targetElement.appendChild(spinner);
};

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('form');
    form.addEventListener("submit", addSpinner);
});
