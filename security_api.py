from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
# Active CORS pour autoriser les requêtes venant de votre site web
CORS(app)

@app.route('/')
def index():
    # S'assure de renvoyer votre page HTML principale (située dans le dossier templates)
    return render_template('index.html')

@app.route('/api/audit', methods=['POST'])
def audit_password():
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        # Logique de vérification basique de robustesse
        if not password:
            return jsonify({"status": "error", "message": "Mot de passe vide"}), 400
            
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Le mot de passe doit faire au moins 8 caractères.")
            
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Ajoutez des majuscules.")
            
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Ajoutez des chiffres.")
            
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Ajoutez des caractères spéciaux.")

        is_secure = score >= 3
        
        return jsonify({
            "status": "success",
            "secure": is_secure,
            "score": score,
            "feedback": feedback,
            "message": "Mot de passe sécurisé !" if is_secure else "Mot de passe trop faible."
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/breach', methods=['POST'])
def check_breach():
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        if not email or '@' not in email:
            return jsonify({"status": "error", "message": "Adresse e-mail invalide"}), 400
            
        # Simulation de vérification de fuite (à connecter à une API externe si besoin)
        # Par défaut, on simule qu'aucune fuite n'a été trouvée pour cet exemple
        return jsonify({
            "status": "success",
            "leached": False,
            "message": f"Aucune fuite détectée pour l'adresse : {email}"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Render utilise un port dynamique ou le port 5000 par défaut en local
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)