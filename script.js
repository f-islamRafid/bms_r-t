const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');

// Toggle forms
registerBtn.addEventListener('click', () => { container.classList.add("active"); });
loginBtn.addEventListener('click', () => { container.classList.remove("active"); });

// --- Registration ---
const registerForm = document.querySelector('.sign-up form');
const registerMessage = document.getElementById('register-message');

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const name = registerForm.querySelector('input[placeholder="Name"]').value;
    const email = registerForm.querySelector('input[placeholder="Email"]').value;
    const password = registerForm.querySelector('input[placeholder="Password"]').value;

    try {
        const res = await fetch('http://127.0.0.1:5000/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });

        const data = await res.json();
        registerMessage.textContent = data.message;
        registerMessage.style.color = data.status === 'success' ? 'green' : 'red';

    } catch (err) {
        console.error(err);
        registerMessage.textContent = 'Registration failed';
        registerMessage.style.color = 'red';
    }
});

// --- Login ---
const loginForm = document.querySelector('.sign-in form');
const loginMessage = document.getElementById('login-message');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = loginForm.querySelector('input[placeholder="Email"]').value;
    const password = loginForm.querySelector('input[placeholder="Password"]').value;

    try {
        const res = await fetch('http://127.0.0.1:5000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        loginMessage.textContent = data.message || 'Login successful';
        loginMessage.style.color = data.status === 'success' ? 'green' : 'red';

        if (data.status === 'success') {
            localStorage.setItem('token', data.token);
        }

    } catch (err) {
        console.error(err);
        loginMessage.textContent = 'Login failed';
        loginMessage.style.color = 'red';
    }
});
