// Force user to agree to terms & conditions
addEventListener('DOMContentLoaded', () => {
    // Disable register button
    const registerButton = document.getElementById('registerButton');
    registerButton.disabled = true;

    // Enable register button when agreeButton is clicked and hide modal
    const agreeButton = document.getElementById('agreeButton');
    agreeButton.addEventListener('click', () => {
        registerButton.disabled = false;
    })
});