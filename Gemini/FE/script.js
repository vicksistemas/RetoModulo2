const API_BASE_URL = 'http://localhost:8000'; // Se asume el puerto expuesto del BE

// Comprueba si ya estamos autenticados y redirige si es necesario
function checkAuthAndRedirect() {
    const token = localStorage.getItem('userToken');
    const path = window.location.pathname;
    
    if (token && path.includes('index.html')) {
        window.location.href = 'dashboard.html';
    } else if (!token && path.includes('dashboard.html')) {
        window.location.href = 'index.html';
    }
}
checkAuthAndRedirect(); // Llama en cada carga de página

// ------------------- LÓGICA DE AUTENTICACIÓN -------------------

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            handleLogin();
        });
    }
});

async function handleLogin() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const messageEl = document.getElementById('message');
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login?username=${username}&password=${password}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('userToken', data.access_token);
            messageEl.textContent = "Login exitoso. Redirigiendo...";
            window.location.href = 'dashboard.html';
        } else {
            messageEl.textContent = data.detail || "Error de credenciales.";
        }
    } catch (error) {
        messageEl.textContent = "Error de conexión con el servidor.";
    }
}

function handleLogout() {
    localStorage.removeItem('userToken');
    window.location.href = 'index.html';
}

async function handleRegister() {
    // Implementación de registro simplificada
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;
    const messageEl = document.getElementById('message');

    // Aquí iría la lógica completa de registro con más campos (edad, género, estado)
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register?username=${username}&password=${password}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Simulamos solo el envío de usuario y contraseña por simplicidad
            body: JSON.stringify({ username, password, full_name: "Nuevo Usuario", birth_date: "2000-01-01", gender: "Male", state: "CDMX" })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            messageEl.textContent = "Registro exitoso. ¡Inicia sesión!";
            document.getElementById('register-form').style.display = 'none';
        } else {
            messageEl.textContent = data.detail || "Error al registrar usuario.";
        }
    } catch (error) {
        messageEl.textContent = "Error de conexión para el registro.";
    }
}

// ------------------- LÓGICA DEL DASHBOARD -------------------

async function loadDashboard() {
    const token = localStorage.getItem('userToken');
    if (!token) return;

    try {
        const response = await fetch(`${API_BASE_URL}/stats/dashboard`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            handleLogout(); // Forzar logout si el token es inválido
            return;
        }

        const data = await response.json();
        renderCharts(data);

    } catch (error) {
        console.error("Error al cargar el dashboard:", error);
    }
}

function renderCharts(stats) {
    // Gráfico de Edad
    const ageCtx = document.getElementById('ageChart').getContext('2d');
    new Chart(ageCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(stats.age_distribution),
            datasets: [{
                label: 'Usuarios por Rango de Edad',
                data: Object.values(stats.age_distribution),
                backgroundColor: ['#007bff', '#28a745', '#ffc107'],
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true } }
        }
    });

    // Gráfico de Género
    const genderCtx = document.getElementById('genderChart').getContext('2d');
    new Chart(genderCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(stats.gender_distribution),
            datasets: [{
                label: 'Usuarios por Género',
                data: Object.values(stats.gender_distribution),
                backgroundColor: ['#17a2b8', '#fd7e14'],
            }]
        },
        options: { responsive: true }
    });
    
    // Gráfico de Distribución por Estados
    const stateCtx = document.getElementById('stateChart').getContext('2d');
    new Chart(stateCtx, {
        type: 'polarArea',
        data: {
            labels: Object.keys(stats.state_distribution),
            datasets: [{
                label: 'Usuarios por Estado',
                data: Object.values(stats.state_distribution),
                backgroundColor: ['#6f42c1', '#e83e8c', '#20c997', '#dc3545', '#6c757d'],
            }]
        },
        options: { responsive: true }
    });
}