document.addEventListener("DOMContentLoaded", () => {
    // --- 1. GESTION DE L'AUDIT DE MOT DE PASSE ---
    // Remplacez 'btn-analyser' par l'ID réel de votre bouton d'analyse de mot de passe dans votre HTML
    const btnAudit = document.querySelector("#btn-analyser") || document.getElementById("analyser-mdp"); 
    const inputPassword = document.querySelector("#password-input") || document.querySelector("input[type='password']");

    if (btnAudit && inputPassword) {
        btnAudit.addEventListener("click", async (e) => {
            e.preventDefault();
            const password = inputPassword.value;

            if (!password) {
                alert("Veuillez saisir un mot de passe à tester.");
                return;
            }

            try {
                // Utilisation d'une URL relative pour communiquer avec le backend
                const response = await fetch('/api/audit', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: password })
                });

                const result = await response.json();

                if (response.ok) {
                    // Succès de la communication : affiche le résultat
                    console.log("Résultat de l'audit :", result);
                    alert(result.message);
                } else {
                    // Erreur renvoyée par le serveur
                    alert("Erreur : " + (result.message || "Impossible d'analyser le mot de passe."));
                }
            } catch (error) {
                console.error("Erreur de connexion au serveur :", error);
                alert("❌ Impossible de joindre le serveur de sécurité.");
            }
        });
    }

    // --- 2. GESTION DE LA SURVEILLANCE DES FUITES D'E-MAIL ---
    // Remplacez par les sélecteurs correspondant à votre formulaire e-mail
    const btnEmail = document.querySelector("#btn-email") || document.querySelector("button:not(#btn-analyser)");
    const inputEmail = document.querySelector("#email-input") || document.querySelector("input[type='email']");

    if (btnEmail && inputEmail) {
        btnEmail.addEventListener("click", async (e) => {
            e.preventDefault();
            const email = inputEmail.value;

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

                const result = await response.json();

                if (response.ok) {
                    console.log("Résultat fuite e-mail :", result);
                    alert(result.message);
                } else {
                    alert("Erreur : " + (result.message || "Investigation impossible."));
                }
            } catch (error) {
                console.error("Erreur de connexion au serveur :", error);
                alert("❌ Impossible de joindre le serveur de sécurité.");
            }
        });
    }
});