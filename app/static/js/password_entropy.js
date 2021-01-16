const stringEntropy = (string) => {
    const maxCharValue = 65535;

    const values = [];
    for (let i = 0; i < string.length; i++) {
        values.push(string.charCodeAt(i));
    }
    const uniqueValues = new Set(values);

    const log = Math.log2(maxCharValue)
    const entropy = uniqueValues.size * log;
    const maxEntropy = string.length * log;

    return [entropy, maxEntropy];
};

const handelPasswordChange = (e) => {
    const password = e.target.value;

    const [entropy, maxEntropy] = stringEntropy(password);
    const procentage = entropy / maxEntropy * 100;

    const entropyOutput = document.getElementById('entropy-value');
    const text = isFinite(procentage) ? `${entropy.toFixed(0)} / ${maxEntropy.toFixed()}` : '';
    entropyOutput.innerText = text;

    const entropyBar = document.getElementById('entropy-progress-bar');
    const barValue = isFinite(procentage) ? procentage : 0;
    entropyBar.style.width = `${barValue}%`;
    entropyBar.setAttribute('aria-valuenow', barValue);
};

document.addEventListener('DOMContentLoaded', () => {
    const password = document.getElementById('password');
    password.addEventListener('input', handelPasswordChange);
});