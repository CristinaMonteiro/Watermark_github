from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from flask_bcrypt import Bcrypt #encriptar hash+salt
import re #valida se a pass é forte
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from config import app, mail #email
from flask_mail import Message #email
from flask import send_file
from io import BytesIO
import requests
import os
from flask import send_from_directory #temporario - fazer download result1.jpg
from werkzeug.utils import secure_filename
import glob
from werkzeug.utils import secure_filename 
import zipfile
import subprocess
import json

CORS(app)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'chave-super-secreta'
jwt = JWTManager(app)

#alteração de mongodb local para mongodb atlas
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['watermark']
collectionImagesLogs = db['imagesLogs']
collectionUsers = db['users']

PYTORCH_SERVE_URL = "http://localhost:8080/predictions/autoencoder"

#para limitar o numero de vezes que o user tenta fazer login (5x a cada 10min)
login_attempts = {}
MAX_ATTEMPTS = 5
BLOCK_TIME = timedelta(minutes=10)

#para validar a pass
def is_strong_password(password):
    # No minimo: 8 caracteres, 1 maiúscula, 1 minúscula, 1 número, 1 símbolo
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password))

@app.route('/register', methods=['POST'])
def register():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        
        data = request.get_json()
        nif = data.get('nif')
        email = data.get('email')
        password = data.get('password')
        

        if not nif or not email or not password:
            return jsonify({'error': 'NIF, Email e password são obrigatórios.'}), 400

        if collectionUsers.find_one({'nif': nif}) or collectionUsers.find_one({'email': email}):
            return jsonify({'error': 'Utilizador já existe.'}), 409
      
        if not is_strong_password(password):
            return jsonify({'error': 'A password deve ter no mínimo 8 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.'}), 400


        # Password hash with salt, em que o bcrypt por defeito faz rounds=12 
        # o que significa 2^12=4096 iterações ao gerar o hash.
        # neste caso defini como 14 para ser ainda mais seguro, mas tambem torna mais lento
        hashed_password = bcrypt.generate_password_hash(password, rounds=14).decode('utf-8')

        collectionUsers.insert_one({
            'nif': nif,
            'email': email,
            'password': hashed_password
        })

        return jsonify({'message': 'Utilizador registado com sucesso!'}), 201

    except Exception as e:
        print('Erro no /register:', e)
        return jsonify({'error': 'Erro interno do servidor'}), 500


@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415

    data = request.get_json()
    nif = data.get('nif')
    password = data.get('password')


    #limitar as tentativas de login
    ip = request.remote_addr #para ir buscar o ip do user
    now = datetime.now()

    attempts = login_attempts.get(ip, {'count':0, 'last_attempt':now, 'blocked_until':None})

    # Verifica se está temporariamente bloqueado
    if attempts['blocked_until'] and now < attempts['blocked_until']:
        return jsonify({'error': 'Demasiadas tentativas. Tenta novamente mais tarde.'}), 429
    

    if not nif or not password:
        return jsonify({'error': 'NIF e password são obrigatórios.'}), 400

    user = collectionUsers.find_one({'nif': nif})
    if user and bcrypt.check_password_hash(user['password'], password):
        #limpa o numero de tentativas
        login_attempts.pop(ip, None)
        access_token = create_access_token(identity=nif)
        return jsonify({'access_token': access_token, 'message': 'Login bem-sucedido!'}), 200  # ADICIONAR

    else:
        #falhou: incrementar numero de tentativas
        attempts['count'] += 1
        attempts['last_attempt'] = now

        # Bloqueia se ultrapassou o limite
        if attempts['count'] >= MAX_ATTEMPTS:
            attempts['blocked_until'] = now + BLOCK_TIME

        login_attempts[ip] = attempts
        return jsonify({'error': 'Credenciais inválidas'}), 401


@app.route('/homepage-data', methods=['GET'])
@jwt_required()
def homepage_data():
    nif = get_jwt_identity()
    return jsonify({
        'message': 'Acesso autorizado à homepage.',
        'nif': nif
    }), 200


@app.route('/log-image-action', methods=['POST'])
@jwt_required()
def log_image_action():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415

        data = request.get_json()
        required_fields = ['nif', 'action', 'fileName', 'status', 'message']

        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Campos obrigatórios em falta no log.'}), 400

        log_entry = {
            'nif': data['nif'],
            'action': data['action'],
            'fileName': data['fileName'],
            'status': data['status'],
            'message': data['message'],
            'timestamp': datetime.now(timezone.utc),
        }

        collectionImagesLogs.insert_one(log_entry)
        return jsonify({'message': 'Log registado com sucesso!'}), 201

    except Exception as e:
        print('Erro ao registar log de imagem:', e)
        return jsonify({'error': 'Erro interno ao registar log'}), 500


@app.route("/send_mail", methods=["POST"])
def send_mail():
    try:
        data = request.get_json()
        nif = data.get("nif")

        if not nif:
            return jsonify({"error": "NIF é obrigatório"}), 400

        user = collectionUsers.find_one({"nif": nif})
        if not user:
            return jsonify({"error": "Utilizador não encontrado"}), 404
        
        #Gerar token, de 15min, para poder redifinir pass via link enviado para o mail
        token = create_access_token(identity=nif, expires_delta=timedelta(minutes=15)) #ALTERAçÃO 
        reset_link = f"http://localhost:3000/redefine-password?token={token}" #ALTERAçÃO

        mail_message = Message(
            'Recuperação de Palavra-Passe - Watermark UBI', 
            sender =   'test@watermark-ubi.pt', 
            recipients=[user["email"]]
        )
        mail_message.body = f"""
        
        Recebemos um pedido para recuperar a sua palavra-passe.\n \
        Clique no seguinte link para redefinir a sua palavra-passe (válido por 15min): \
        {reset_link} \n Se não fez este pedido ignore este e-mail.
        """

        mail.send(mail_message)

        return jsonify({"message": "Email enviado com sucesso!"}), 200

    except Exception as e:
        print("Erro ao enviar email:", e)
        return jsonify({"error": "Erro ao enviar email"}), 500


#para poder fazer reset da password (com token) - ALTERAçÃO
@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get("token")
        new_password = data.get("newPassword")

        if not token or not new_password:
            return jsonify({"error": "Token e nova password são obrigatórios"}), 400

        # 🔍 Tenta decodificar o token e obter o nif
        try:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            nif = decoded["sub"]
        except Exception as e:
            print("Erro ao decodificar token:", e)
            return jsonify({"error": "Sessão inválida ou expirada"}), 401

        # Valida força da nova password
        if not is_strong_password(new_password):
            return jsonify({'error': 'A palavra-passe deve ter no mínimo 8 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.'}), 400

        hashed_password = bcrypt.generate_password_hash(new_password, rounds=14).decode('utf-8')

        result = collectionUsers.update_one(
            {"nif": nif},
            {"$set": {"password": hashed_password}}
        )

        if result.modified_count == 0:
            return jsonify({"error": "Erro ao atualizar a palavra-passe"}), 500

        return jsonify({"message": "Palavra-passe redefinida com sucesso!"}), 200

    except Exception as e:
        print("Erro ao redefinir password:", e)
        return jsonify({"error": "Erro interno ao redefinir password"}), 500


#PARA O MODELO DO FRANCISCO - ADICIONAR SEGREDO NA IMAGEM (UploadDocument.js)
@app.route("/infer-torchserve", methods=["POST"])
@jwt_required()
def infer_torchserve():
    try:
        data = request.get_json()
        nif = get_jwt_identity()
        
        image_b64 = data.get("image")
        secret = data.get("secret")

        if not image_b64 or not secret:
            return jsonify({"error": "Campos 'image' e 'secret' são obrigatórios."}), 400
        
        if len(secret) > 6:
            return jsonify({"error": "Segredo demasiado longo. Máximo 6 caracteres."}), 400


        # Enviar para TorchServe
        ts_url = "http://localhost:8080/predictions/autoencoder"
        headers = {"Content-Type": "application/json"}
        payload = {
            "image": image_b64,
            "secret": secret
        }

        response = requests.post(ts_url, headers=headers, json=payload)
        response.raise_for_status()

        # Debugging
        print("Enviando para TorchServe:", ts_url)
        print(f"Backend: {image_b64} - {secret}")
        print("Resposta TorchServe:", response.text)
        
        response_data = response.json()
        print("DEBUG: TorchServe retornou:", response_data)

        if "stego_base64" not in response_data:
            raise Exception("TorchServe não retornou imagem estego.")

        stego_base64 = response_data["stego_base64"]


        # Registo no MongoDB
        collectionImagesLogs.insert_one({
            "nif": nif,
            "action": "Inferência",
            "fileName": "via_base64",
            "status": "Sucesso",
            "message": f"Imagem processada com segredo '{secret}'",
            "timestamp": datetime.now(timezone.utc),
        })

        return jsonify({
            "stego_image_base64": stego_base64,
            "message": "Inferência realizada com sucesso!"
        }), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Erro ao contactar TorchServe: {str(e)}"}), 500

    except Exception as e:
        import traceback
        print("Erro em /infer-torchserve:")
        traceback.print_exc()  # Mostra a stack completa
        return jsonify({"error": f"Erro interno durante a inferência: {str(e)}"}), 500


#PARA O MODELO DO FRANCISCO - VERIFICAR SE A IMAGEM TEM SEGREDO (verifyDocument.js)
@app.route("/verify-torchserve", methods=["POST"])
@jwt_required()
def verify_torchserve():
    try:
        data = request.get_json()
        nif = get_jwt_identity()

        image_b64 = data.get("image")
        if not image_b64:
            return jsonify({"error": "Campo 'image' é obrigatório."}), 400

        # Enviar para TorchServe (sem segredo, só a imagem)
        ts_url = "http://localhost:8080/predictions/autoencoder"
        headers = {"Content-Type": "application/json"}
        payload = {
            "image": image_b64
        }

        response = requests.post(ts_url, headers=headers, json=payload)
        response.raise_for_status()

        print("Resposta TorchServe (verify):", response.text)
        response_data = response.json()

        # TorchServe deverá devolver algo como {"has_secret": true, "secret": "abc"}
        has_secret = response_data.get("has_secret", False)
        secret = response_data.get("secret", None)

        # Log no Mongo
        collectionImagesLogs.insert_one({
            "nif": nif,
            "action": "Verificação",
            "fileName": "via_base64",
            "status": "Sucesso" if has_secret else "Sem segredo",
            "message": f"Resultado da verificação: {secret if secret else 'nenhum segredo'}",
            "timestamp": datetime.now(timezone.utc),
        })

        return jsonify({
            "has_secret": has_secret,
            "secret": secret
        }), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Erro ao contactar TorchServe: {str(e)}"}), 500

    except Exception as e:
        import traceback
        print("Erro em /verify-torchserve:")
        traceback.print_exc()
        return jsonify({"error": f"Erro interno durante a verificação: {str(e)}"}), 500


#Para a pagina redefinirPassword receber o email do user
@app.route("/user-data", methods=["GET"])
@jwt_required()
def user_data():
    try:
        nif = get_jwt_identity()
        user = collectionUsers.find_one({"nif": nif})

        if not user:
            return jsonify({"error": "Utilizador não encontrado"}), 404

        return jsonify({
            "email": user["email"],
            "nif": user["nif"]
        }), 200

    except Exception as e:
        print("Erro em /user-data:", e)
        return jsonify({"error": "Erro interno"}), 500

        






#Páginas de Erro
@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({"error": "Acesso proibido"}), 403

# Handler para erro 404 - Not Found (Página não encontrada)
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Página não encontrada"}), 404

# Handler para erro 500 - Internal Server Error (Erro interno do servidor)
@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Erro interno do servidor"}), 500


@app.route('/admin-only')
@jwt_required()
def admin_only_route():
    nif = get_jwt_identity()
    user = collectionUsers.find_one({'nif': nif})
    
    if not user.get('is_admin', False):
        # Pode retornar diretamente o JSON:
        return jsonify({'error': 'Acesso proibido'}), 403
        # Ou usar abort para disparar o handler:
        # abort(403)

    return jsonify({'message': 'Acesso autorizado'}), 200






if __name__ == '__main__':
   app.run(debug = True)