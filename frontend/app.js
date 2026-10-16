/*
 * CyberGuard — logique de l'interface.
 *
 * Trois règles tenues ici, comme côté serveur :
 *
 * 1. Aucune donnée n'est insérée avec innerHTML. Tout ce qui vient de
 *    l'utilisateur ou de l'API est écrit avec textContent : un texte hostile
 *    reste un texte, il ne devient jamais du code.
 * 2. Le mot de passe ne quitte jamais le navigateur. On calcule son empreinte
 *    SHA-1 localement et on n'envoie que les cinq premiers caractères
 *    (k-anonymity) ; la comparaison finale se fait ici.
 * 3. Le score de robustesse est calculé localement, avec les mêmes règles que
 *    le module Python « app/scoring.py ».
 */

const CHAMP_MOT_DE_PASSE = document.getElementById("password-input");
const BOUTON_OEIL = document.getElementById("toggle-password");
const BOUTON_ANALYSE = document.getElementById("btn-analyser");
const BOUTON_EMAIL = document.getElementById("btn-email");

/* ------------------------------------------------------------------ outils */

/** Empreinte SHA-1 en hexadécimal, calculée par le navigateur. */
async function empreinteSha1(texte) {
    const donnees = new TextEncoder().encode(texte);
    const empreinte = await crypto.subtle.digest("SHA-1", donnees);
    return Array.from(new Uint8Array(empreinte))
        .map((octet) => octet.toString(16).padStart(2, "0"))
        .join("");
}

/** Vide un élément puis y place du texte — jamais du HTML. */
function afficherTexte(element, texte) {
    element.replaceChildren(document.createTextNode(texte));
}

/** Construit un élément avec sa classe et son texte. */
function element(balise, classe, texte) {
    const noeud = document.createElement(balise);
    if (classe) noeud.className = classe;
    if (texte !== undefined) noeud.textContent = texte;
    return noeud;
}

/** Icône Font Awesome. */
function icone(classe) {
    return element("i", `fa-solid ${classe}`);
}

/** Remplit un bouton avec un texte et une icône, sans innerHTML. */
function remplirBouton(bouton, texte, classeIcone) {
    const contenu = [];
    if (classeIcone) contenu.push(icone(classeIcone));
    contenu.push(element("span", null, texte));
    bouton.replaceChildren(...contenu);
}

/* --------------------------------------------------- robustesse (miroir Python) */

const LONGUEUR_SOLIDE = 12;
const LONGUEUR_MINIMALE = 8;
const SUITES = [
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop", "azertyuiop", "motdepasse", "password", "admin",
];

/** Reproduit exactement les règles de app/scoring.py. */
function evaluerMotDePasse(motDePasse) {
    const minuscule = motDePasse.toLowerCase();
    const faiblesses = [];

    let varietes = 0;
    if (/[a-z]/.test(motDePasse)) varietes += 1;
    if (/[A-Z]/.test(motDePasse)) varietes += 1;
    if (/\d/.test(motDePasse)) varietes += 1;
    if (/[^A-Za-z0-9]/.test(motDePasse)) varietes += 1;

    let score = 0;
    if (motDePasse.length >= LONGUEUR_MINIMALE) score += 1;
    if (motDePasse.length >= LONGUEUR_SOLIDE) score += 1;
    if (varietes >= 3) score += 1;
    if (varietes === 4) score += 1;

    if (motDePasse.length < LONGUEUR_MINIMALE) {
        faiblesses.push(`moins de ${LONGUEUR_MINIMALE} caractères`);
    }
    if (varietes < 3) {
        faiblesses.push("mélangez majuscules, minuscules, chiffres et symboles");
    }
    if (SUITES.some((suite) => minuscule.includes(suite))) {
        faiblesses.push("contient une suite connue (clavier, alphabet, mot courant)");
        score = Math.max(0, score - 1);
    }
    if (/(.)\1{2,}/.test(motDePasse)) {
        faiblesses.push("contient un caractère répété trois fois ou plus");
        score = Math.max(0, score - 1);
    }

    return { score: Math.min(score, 4), longueur: motDePasse.length, faiblesses };
}

function conseilsPour(score) {
    if (score <= 1) {
        return [
            "Mot de passe très vulnérable aux attaques par dictionnaire.",
            "Allongez-le à 12 caractères au minimum.",
            "Combinez majuscules, minuscules, chiffres et symboles.",
            "Évitez les suites logiques et les données personnelles.",
        ];
    }
    if (score <= 3) {
        return [
            "Bonne base : il peut encore être renforcé.",
            "Ajoutez des caractères spéciaux non standard pour contrer le bruteforce.",
            "Ne réutilisez pas ce mot de passe sur d'autres services sensibles.",
        ];
    }
    return [
        "Très bonne résistance face aux algorithmes de cassage.",
        "Conservez-le unique à ce service.",
        "Renouvelez-le si le service concerné annonce une fuite.",
    ];
}

/* -------------------------------------------------------- rendu des résultats */

function blocResultat(titre, classeIcone, couleurIcone) {
    const entete = element("div", "result-header");
    const marque = icone(classeIcone);
    marque.style.color = couleurIcone;
    entete.append(marque, element("strong", null, titre));
    return entete;
}

function afficherAudit(resultat, score, fuites, faiblesses) {
    const couleur = score >= 3 ? "var(--neon-green)" : "var(--neon-red)";
    const conteneur = document.getElementById("card-audit");
    conteneur.classList.toggle("scan-green", score >= 3);
    conteneur.classList.toggle("scan-red", score < 3);
    setTimeout(() => conteneur.classList.remove("scan-green", "scan-red"), 1200);

    const corps = element("div", "result-msg");

    const ligneFuite = element("div");
    if (fuites === null) {
        ligneFuite.textContent =
            "Fuite : vérification indisponible pour le moment (réessayez plus tard).";
    } else if (fuites > 0) {
        ligneFuite.textContent =
            `Attention : ce mot de passe apparaît ${fuites.toLocaleString("fr-FR")} fois ` +
            "dans des fuites de données connues. Changez-le partout où vous l'utilisez.";
    } else {
        ligneFuite.textContent =
            "Bonne nouvelle : ce mot de passe n'apparaît dans aucune fuite connue.";
    }
    ligneFuite.style.marginBottom = "8px";
    corps.append(ligneFuite);

    if (faiblesses.length) {
        const liste = element("ul");
        for (const faiblesse of faiblesses) {
            liste.append(element("li", null, faiblesse));
        }
        corps.append(liste);
    }
    for (const conseil of conseilsPour(score)) {
        corps.append(element("div", "conseil", conseil));
    }

    const meta = element("div", "score-meta");
    meta.append(element("span", null, "Indice de robustesse : "));
    const valeur = element("strong", null, `${score} / 4`);
    valeur.style.color = couleur;
    meta.append(valeur);

    const fond = element("div", "score-bar-bg");
    const barre = element("div", "score-bar-fill");
    barre.style.width = `${score * 25}%`;
    barre.style.backgroundColor = couleur;
    fond.append(barre);

    resultat.replaceChildren(
        blocResultat("Rapport d'évaluation cryptographique",
                     score >= 3 ? "fa-circle-check" : "fa-triangle-exclamation", couleur),
        corps, meta, fond,
    );
}

function afficherErreur(resultat, message) {
    const bloc = element("span");
    bloc.style.color = "var(--neon-red)";
    bloc.textContent = message;
    resultat.replaceChildren(bloc);
}

/* ------------------------------------------------------------- interactions */

/* Affichage / masquage du mot de passe : on agit sur le type du champ, la
   valeur n'est jamais recopiée ailleurs. */
BOUTON_OEIL.addEventListener("click", () => {
    const masque = CHAMP_MOT_DE_PASSE.type === "password";
    CHAMP_MOT_DE_PASSE.type = masque ? "text" : "password";
    BOUTON_OEIL.classList.toggle("fa-solid", masque);
    BOUTON_OEIL.classList.toggle("fa-regular", !masque);
    CHAMP_MOT_DE_PASSE.focus();
});

BOUTON_ANALYSE.addEventListener("click", async () => {
    const motDePasse = CHAMP_MOT_DE_PASSE.value;
    const resultat = document.getElementById("result-audit");

    if (!motDePasse) {
        alert("Veuillez saisir un mot de passe ou une chaîne.");
        return;
    }

    remplirBouton(BOUTON_ANALYSE, "Analyse en cours...", "fa-spinner fa-spin");
    BOUTON_ANALYSE.disabled = true;

    const { score, faiblesses } = evaluerMotDePasse(motDePasse);

    let fuites = null;
    try {
        const empreinte = await empreinteSha1(motDePasse);
        const prefixe = empreinte.slice(0, 5);
        const suffixe = empreinte.slice(5);

        const reponse = await fetch("/api/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prefixe_sha1: prefixe }),
        });

        if (reponse.ok) {
            const donnees = await reponse.json();
            fuites = Number(donnees.empreintes[suffixe] || 0);
        }
    } catch (erreur) {
        fuites = null;   // on ne prétend rien si la vérification n'a pas abouti
    } finally {
        resultat.style.display = "block";
        afficherAudit(resultat, score, fuites, faiblesses);
        remplirBouton(BOUTON_ANALYSE, "Lancer l'audit de robustesse", "fa-arrow-right");
        BOUTON_ANALYSE.disabled = false;
        // La valeur saisie est effacée du champ dès la fin de l'analyse.
        CHAMP_MOT_DE_PASSE.value = "";
    }
});

BOUTON_EMAIL.addEventListener("click", async () => {
    const champEmail = document.getElementById("email-input");
    const email = champEmail.value;
    const resultat = document.getElementById("result-email");
    const conteneur = document.getElementById("card-email");

    if (!email) {
        alert("Veuillez saisir un e-mail.");
        return;
    }

    remplirBouton(BOUTON_EMAIL, "Recherche en cours...", "fa-spinner fa-spin");
    BOUTON_EMAIL.disabled = true;
    conteneur.classList.add("scan-cyan");
    setTimeout(() => conteneur.classList.remove("scan-cyan"), 1200);

    try {
        const reponse = await fetch("/api/breach", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email }),
        });
        const donnees = await reponse.json().catch(() => ({}));

        const corps = element("div", "result-msg");
        if (reponse.ok) {
            corps.textContent = donnees.message || "Analyse terminée.";
            if (Array.isArray(donnees.fuites) && donnees.fuites.length) {
                const liste = element("ul");
                for (const fuite of donnees.fuites) {
                    liste.append(element("li", null, String(fuite)));
                }
                corps.append(liste);
            }
        } else {
            // Message honnête du serveur : ni « aucune fuite », ni promesse vide.
            corps.textContent = donnees.detail || "Investigation impossible.";
        }

        const cible = element("div", "scan-target");
        cible.append(element("span", null, "Périmètre audité : "));
        const code = element("code", null, email);   // textContent : jamais du HTML
        cible.append(code);

        resultat.style.display = "block";
        resultat.replaceChildren(
            blocResultat("Résultat de l'investigation", "fa-shield-halved", "var(--neon-cyan)"),
            corps, cible,
        );
    } catch (erreur) {
        resultat.style.display = "block";
        afficherErreur(resultat, "Erreur réseau.");
    } finally {
        remplirBouton(BOUTON_EMAIL, "Lancer l'investigation", "fa-magnifying-glass");
        BOUTON_EMAIL.disabled = false;
    }
});
