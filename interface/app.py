from flask import Flask, render_template, request, redirect, url_for, flash
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'cle_secrete_a_personnaliser'  # Requise pour flash()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    message = None
    if request.method == 'POST':
        common_name = request.form['common_name']
        cert_type = request.form['cert_type']  # "utilisateur" ou "serveur"
        validity = request.form['validity']
        password = request.form['password']

        key_path = f"../intermediate/private/{common_name}.key.pem"
        csr_path = f"../intermediate/csr/{common_name}.csr"
        cert_path = f"../intermediate/certs/{common_name}.cert.pem"

        try:
            # Créer les dossiers si besoin
            os.makedirs("../intermediate/private", exist_ok=True)
            os.makedirs("../intermediate/csr", exist_ok=True)
            os.makedirs("../intermediate/certs", exist_ok=True)

            # 1. Générer une clé privée
            subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)

            # 2. Créer une CSR
            subprocess.run([
                "openssl", "req", "-new", "-key", key_path,
                "-out", csr_path,
                "-subj", f"/C=MA/ST=Rabat/O=PKI Org/CN={common_name}"
            ], check=True)

            # 3. Signer la CSR avec l’intermédiaire
            ext_section = "usr_cert" if cert_type == "utilisateur" else "server_cert"
            subprocess.run([
                "openssl", "ca", "-config", "../intermediate/openssl.cnf",
                "-extensions", ext_section,
                "-days", validity,
                "-notext", "-md", "sha256",
                "-in", csr_path,
                "-out", cert_path,
                "-batch",
                "-passin", f"pass:{password}"
            ], check=True)

            message = f"✅ Certificat généré avec succès pour {common_name} ({cert_type}), validité {validity} jours."

        except subprocess.CalledProcessError as e:
            message = f"❌ Erreur lors de la génération : {e.stderr or str(e)}"

    return render_template('generate.html', message=message)

@app.route('/revoke', methods=['GET', 'POST'])
def revoke():
    if request.method == 'POST':
        cert_type = request.form['cert_type']
        common_name = request.form['common_name']
        password = request.form['password']

        cert_path = f"../intermediate/certs/{common_name}.cert.pem"

        if not os.path.exists(cert_path):
            flash("Le certificat n'existe pas.", "error")
            return redirect(url_for('revoke'))

        try:
            subprocess.run([
                "openssl", "ca",
                "-config", "../intermediate/openssl.cnf",
                "-revoke", cert_path,
                "-passin", f"pass:{password}"
            ], check=True)

            subprocess.run([
                "openssl", "ca",
                "-config", "../intermediate/openssl.cnf",
                "-gencrl",
                "-out", "../intermediate/crl/intermediate.crl.pem",
                "-passin", f"pass:{password}"
            ], check=True)

            flash(f"Certificat pour {common_name} révoqué avec succès.", "success")

        except subprocess.CalledProcessError:
            flash("Erreur lors de la révocation. Vérifiez les informations fournies.", "error")

        return redirect(url_for('revoke'))

    return render_template('revoke.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        common_name = request.form['common_name']
        cert_type = request.form['cert_type']

        cert_path = f"../intermediate/certs/{common_name}.cert.pem"
        crl_path = "../intermediate/crl/intermediate.crl.pem"
        chain_path = "../intermediate/certs/ca-chain.cert.pem"

        if not os.path.exists(cert_path):
            flash("Le certificat n'existe pas.", "error")
            return redirect(url_for('verify'))

        try:
            result = subprocess.run([
                "openssl", "verify",
                "-crl_check",
                "-CAfile", chain_path,
                "-CRLfile", crl_path,
                cert_path
            ], capture_output=True, text=True, check=True)

            if "OK" in result.stdout:
                flash(f"✅ Certificat {common_name} valide.", "success")
            else:
                flash(f"❌ Certificat {common_name} invalide : {result.stdout}", "error")

        except subprocess.CalledProcessError as e:
            flash(f"Erreur de vérification : {e.stderr or str(e)}", "error")

        return redirect(url_for('verify'))

    return render_template('verify.html')


if __name__ == '__main__':
    app.run(debug=True)