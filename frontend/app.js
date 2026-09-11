const API_URL = "https://cyberguard-v8x6.onrender.com/api"

async function checkPassword() {
    const passwordInput = document.getElementById("passwordInput");
    const resultDiv = document.getElementById("passwordResult");
    const password = passwordInput.value.trim();
    
    if (!password) {
        resultDiv.innerHTML = "<p style='color:#ff4d4d;'>⚠️ Veuillez entrer un mot de passe.</p>";
        return;
    }

    resultDiv.innerHTML = "<p style='color:#00E5FF;'>⚡ Analyse en cours...</p>";

    try {
        const response = await fetch(`${API_URL}/check-password`, {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ "password": password })
        });

        if (!response.ok) {
            throw new Error(`Erreur serveur: ${response.status}`);
        }

        const data = await response.json();

        let html = `<p><strong>Force :</strong> <span style='color:#00E5FF;'>${data.strength}</span></p>`;
        if (data.warning) {
            html += `<p style='color:#ffaa00;'>⚠️ <strong>Attention :</strong> ${data.warning}</p>`;
        }
        if (data.suggestions && data.suggestions.length > 0) {
            html += "<p style='color:#00A8FF;'><strong>Conseils :</strong></p><ul>";
            data.suggestions.forEach(s => html += `<li>${s}</li>`);
            html += "</ul>";
        }
        resultDiv.innerHTML = html;

    } catch (error) {
        console.error(error);
        resultDiv.innerHTML = `<p style='color:#ff4d4d;'>❌ Erreur de connexion au serveur (${error.message}). Vérifiez que uvicorn tourne bien.</p>`;
    }
}

async function checkEmail() {
    const emailInput = document.getElementById("emailInput");
    const resultDiv = document.getElementById("emailResult");
    const email = emailInput.value.trim();
    
    if (!email) {
        resultDiv.innerHTML = "<p style='color:#ff4d4d;'>⚠️ Veuillez entrer une adresse e-mail.</p>";
        return;
    }

    resultDiv.innerHTML = "<p style='color:#00E5FF;'>⚡ Recherche des fuites...</p>";

    try {
        const response = await fetch(`${API_URL}/check-email`, {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ "email": email })
        });

        if (!response.ok) {
            throw new Error(`Erreur serveur: ${response.status}`);
        }

        const data = await response.json();

        if (data.compromised) {
            let html = "<p style='color:#ff4d4d;'>🚨 <strong>Adresse compromise !</strong> Présente dans ces fuites :</p><ul>";
            data.breaches.forEach(b => html += `<li style='color:#ffaa00;'>${b}</li>`);
            html += "</ul>";
            resultDiv.innerHTML = html;
        } else {
            resultDiv.innerHTML = "<p style='color:#00ff88;'>✅ <strong>Excellente nouvelle !</strong> Aucune fuite trouvée.</p>";
        }

    } catch (error) {
        console.error(error);
        resultDiv.innerHTML = `<p style='color:#ff4d4d;'>❌ Erreur de connexion au serveur (${error.message}). Vérifiez que uvicorn tourne bien.</p>`;
    }
}