document.addEventListener("DOMContentLoaded", () => {
    console.log("CyberGuard JS chargé avec succès !");

    // 1. Audit de Mot de Passe
    const btnAnalyser = document.getElementById("btn-analyser");
    const passwordInput = document.getElementById("password-input");
    const resultAudit = document.getElementById("result-audit");

    if (btnAnalyser && passwordInput) {
        btnAnalyser.addEventListener("click", async () => {
            const password = passwordInput.value;

            if (!password) {
                alert("Veuillez saisir un mot de passe à tester.");
                return;
            }

            try {
                const response = await fetch('/api/audit', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: password })
                });

                const data = await response.json();

                if (response.ok) {
                    resultAudit.style.display = "block";
                    resultAudit.innerHTML = `<strong>Résultat :</strong> ${data.message} <br><strong>Score :</strong> ${data.score} / 4`;
                } else {
                    resultAudit.style.display = "block";
                    resultAudit.innerHTML = `<span style="color: #EF4444;">Erreur : ${data.detail || "Impossible d'analyser"}</span>`;
                }
            } catch (error) {
                console.error("Erreur réseau :", error);
                resultAudit.style.display = "block";
                resultAudit.innerHTML = `<span style="color: #EF4444;">❌ Impossible de joindre le serveur de sécurité.</span>`;
            }
        });
    }

    // 2. Fuite E-mail
    const btnEmail = document.getElementById("btn-email");
    const emailInput = document.getElementById("email-input");
    const resultEmail = document.getElementById("result-email");

    if (btnEmail && emailInput) {
        btnEmail.addEventListener("click", async () => {
            const email = emailInput.value;

            if (!email) {
                alert("Veuillez saisir une adresse e-mail.");
                return;
            }

            try {
                const response = await fetch('/api/breach', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email: email })
                });

                const data = await response.json();

                if (response.ok) {
                    resultEmail.style.display = "block";
                    resultEmail.innerHTML = `<strong>Investigation :</strong> ${data.message}`;
                } else {
                    resultEmail.style.display = "block";
                    resultEmail.innerHTML = `<span style="color: #EF4444;">Erreur : ${data.detail || "Investigation impossible"}</span>`;
                }
            } catch (error) {
                console.error("Erreur réseau :", error);
                resultEmail.style.display = "block";
                resultEmail.innerHTML = `<span style="color: #EF4444;">❌ Impossible de joindre le serveur de sécurité.</span>`;
            }
        });
    }
});