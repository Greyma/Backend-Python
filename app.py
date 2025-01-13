from flask import Flask, jsonify, request , send_file , Response
from Mongodb_class.Mongo_connect import MongoDBConnection
from flask import Flask, request, jsonify
from functools import wraps
from jwt import decode, ExpiredSignatureError, InvalidTokenError
from dotenv import load_dotenv
from classes.Controller.observer import ConcreteObserver
from flask_cors import CORS
import os
from classes.Controller.Controllers import (
  EtudiantController ,EnseignantsController ,CoursController, MatierController,TestemonialController, CouponController
    )
from werkzeug.utils import secure_filename
import uuid
import xml.etree.ElementTree as ET
import io
import ffmpeg

import requests

load_dotenv()
SECRET_KEY =  os.getenv("SECRET_KEY")
uri = os.getenv("uri")
db_name = os.getenv("db_name")
API_KEYS_Generative = os.getenv("API_KEYS_Generative")

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', "webm" , "jpg" ,"img" , "png",}

CORS(app)
db_connection = MongoDBConnection(uri, db_name)

controllers = {
    "etudiants": EtudiantController(db_connection),
    "enseignants": EnseignantsController(db_connection),
    "cours" : CoursController(db_connection),
    "matieres" : MatierController(db_connection),
    "testimonials" : TestemonialController(db_connection),
    "coupons":  CouponController(db_connection),
}

controllers_classes = [
     EtudiantController,EnseignantsController,CoursController, MatierController , TestemonialController
 ,CouponController
]

# Initialisation de l'observateur unique (Singleton)
observer = ConcreteObserver()

# Générer dynamiquement tous les contrôleurs et ajouter l'observateur
controllers_instances = []

for ControllerClass in controllers_classes:

    controller = ControllerClass(db_connection)

    controller.add_observer(observer)

    controllers_instances.append(controller)


def add_item(controller_name):
    data = request.json
    print(data  )
    controllers[controller_name].add(data)
    return jsonify({"message": f"{controller_name.capitalize()} ajouté avec succès"}), 201

def delete_item(controller_name, item_id):
    controllers[controller_name].delete(item_id)
    return jsonify({"message": f"{controller_name.capitalize()} avec ID {item_id} supprimé."}), 200

def update_item(controller_name, item_id):
    data = request.json
    controllers[controller_name].update(item_id, data)
    return jsonify({"message": f"{controller_name.capitalize()} avec ID {item_id} mis à jour."}), 200

def search_items(controller_name , **criteria):
    results = controllers[controller_name].search(**criteria)
    return jsonify(results), 200

def get_all_items(controller_name) :
    results = controllers[controller_name].get_all()
    return jsonify(results), 200

def token_required(allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = None
            # Vérifier si le token est présent dans le header Authorization
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split(" ")[1]

            if not token:
                return jsonify({'error': 'Token manquant !'}), 401

            try:
                # Décoder le token et récupérer le rôle
                data = decode(token, SECRET_KEY, algorithms=['HS256'])
                user_role = data.get('role_id')
                # Vérifier si le rôle de l'utilisateur est autorisé
                if user_role not in allowed_roles:
                    return jsonify({'error': 'Accès non autorisé !'}), 403

            except ExpiredSignatureError:
                return jsonify({'error': 'Token expiré !'}), 401
            except InvalidTokenError:
                return jsonify({'error': 'Token invalide !'}), 401

            # Si tout est correct, exécuter la fonction de la route
            return func(*args, **kwargs)

        return wrapper
    return decorator

@app.route('/<controller_name>', methods=['POST'])
def add(controller_name):
    return add_item(controller_name)

@app.route('/<controller_name>/<item_id>', methods=['DELETE'])
# @token_required(['admin'])
def delete(controller_name, item_id):
    return delete_item(controller_name, item_id)

@app.route('/<controller_name>/<item_id>', methods=['PUT'])
# @token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def update(controller_name, item_id):
    return update_item(controller_name, item_id)

@app.route('/<controller_name>', methods=['GET'])
# @token_required(['admin', 'viewer'])
def get_all(controller_name):
    return get_all_items(controller_name)

@app.route('/<controller_name>/search', methods=['POST'])
# @token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def search(controller_name):
    criteria = request.json
    print(criteria , flush=True)
    return search_items(controller_name , **criteria)


@app.route('/login',methods=['POST'])
def authentificate():
    data = request.json
    token = controllers['etudiants'].authenticate(data['email'],data['password'])
    return token

@app.route('/cours/<cours_id>/etudiants',methods=['POST'])
def add_etudiant_to_cours(cours_id):
    data = request.json
    controllers['cours'].add_etudiant(cours_id, data['etudiant'])
    return jsonify({"message": "Etudiant ajouté avec succès"}), 201
@app.route('/cours/<cours_id>/etudiants',methods=['DELETE'])
def remove_etudiant_from_cours(cours_id):
    data = request.json
    controllers['cours'].remove_etudiant(cours_id, data['etudiant'])
    return jsonify({"message": "Etudiant supprimé avec succès"}), 200

@app.route('/matieres/<matiere_id>/cours',methods=['POST'])
def add_cours_to_matiere(matiere_id):
    data = request.json
    return controllers['matieres'].add_cours(matiere_id, data['cours'])

@app.route('/matieres/<matiere_id>/cours',methods=['DELETE'])
def remove_cours_from_matiere(matiere_id):
    data = request.json
    controllers['matieres'].remove_cours(matiere_id, data['cours'])
    return jsonify({"message": "Cours supprimé avec succès"}), 200
@app.route('/matieres/<matiere_id>/etudiants',methods=['POST'])
def add_etudiant_to_matiere(matiere_id):
    data = request.json
    return controllers['matieres'].add_etudiant(matiere_id, data['etudiant'])
@app.route('/matieres/<matiere_id>/etudiants',methods=['DELETE'])
def remove_etudiant_from_matiere(matiere_id):
    data = request.json
    controllers['matieres'].remove_etudiant(matiere_id, data['etudiant'])
    return jsonify({"message": "Etudiant supprimé avec succès"}), 200
@app.route('/coupons/use', methods=['POST'])
def use_coupons():
    token = None
    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1]

    if not token:
        return jsonify({'error': 'Token manquant !'}), 401
    etudiant = controllers['etudiants'].verify_token(token)
    print(etudiant)
    coupon_data = request.json
    coupon_code = coupon_data.get('code')
    if not coupon_code:
        return jsonify({'error': 'Coupon code manquant !'}), 400

    result = controllers['coupons'].use_coupon(coupon_code, etudiant.get('etudiant').get('_id'))
    return jsonify(result), 200

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


WEBDAV_URL = os.getenv("CLOUD_URL")
WEBDAV_AUTH = (os.getenv("CLOUD_USER"), os.getenv("CLOUD_PASSWORD"))

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        file = request.files['file']
        filename = secure_filename(file.filename)
        file_path = f"{WEBDAV_URL}{filename}"
        response = requests.put(file_path, data=file.stream, auth=WEBDAV_AUTH)
        if response.status_code == 201:
            return jsonify({"message": "File uploaded successfully", "path": f"/download/{filename}"}), 201
        elif response.status_code == 204:
            return jsonify({"message": "File already exists", "path": f"download/{filename}"}), 200
        else:
            return jsonify({"message": "File not uploaded", "error": response.text}), 400
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/list_files', methods=['GET'])
def list_files():
    try:
        response = requests.request("PROPFIND", WEBDAV_URL, auth=WEBDAV_AUTH)
        if response.status_code == 207:
            tree = ET.fromstring(response.content)
            files = []
            for elem in tree.findall('.//{DAV:}href'):
                file_name = elem.text.split('/')[-1]
                if file_name:  # Exclude empty strings
                    files.append(file_name)
            return jsonify({"files": files}), 200
        else:
            return jsonify({"message": "Failed to list files", "error": response.text}), 400
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        file_url = WEBDAV_URL + filename
        response = requests.get(file_url, auth=WEBDAV_AUTH)
        if response.status_code == 200:
            return send_file(io.BytesIO(response.content), download_name=filename, as_attachment=True)
        else:
            return jsonify({"message": "File not found", "error": response.text}), 404
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/stream/<filename>', methods=['GET'])
def stream_video(filename):
    quality = request.args.get('quality', 'high')  # Default to high quality
    file_url = WEBDAV_URL + filename
    response = requests.get(file_url, auth=WEBDAV_AUTH, stream=True)
    if response.status_code != 200:
        return jsonify({"message": "File not found", "error": response.text}), 404

    def generate():
        if quality == 'low':
            process = (
                ffmpeg
                .input('pipe:0')
                .output('pipe:1', format='mp4', vcodec='libx264', video_bitrate='500k')
                .run_async(pipe_stdin=True, pipe_stdout=True)
            )
        else:
            process = (
                ffmpeg
                .input('pipe:0')
                .output('pipe:1', format='mp4', vcodec='libx264')
                .run_async(pipe_stdin=True, pipe_stdout=True)
            )

        for chunk in response.iter_content(chunk_size=1024):
            process.stdin.write(chunk)
        process.stdin.close()

        while True:
            out_chunk = process.stdout.read(1024)
            if not out_chunk:
                break
            yield out_chunk

        process.stdout.close()
        process.wait()

    return Response(generate(), content_type='video/mp4', direct_passthrough=True)


# Exécution de l'application
if __name__ == '__main__':
    app.run(debug=True )










# @app.route('/addmatiere',methods=['POST'])
# def addmatiere() :
#     data = request.json
#     print(data , flush=True)
#     controllers['matiere'].add(data)
#     return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

# @app.route('/addchapitre',methods=['POST'])
# def chapitre() :
#     data = request.json
#     controllers['matiere'].add_chapitre(data)
#     return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

# @app.route('/to_chapitre',methods=['POST'])
# def to_chapitre() :
#     data = request.json
#     controllers['matiere'].add_etudiant_to_chapitre(data)
#     return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

# @app.route('/to_matiere',methods=['POST'])
# def to_matiere() :
#     data = request.json
#     controllers['matiere'].add_etudiant_to_matiere(data)
#     return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

# @app.route('/generateCode',methods=['POST'])
# def generateCode() :
#     data = request.json
#     results = controllers['matiere'].generate_code(matiere_id=data['matiere_id'], chapitre_id=data['chapitre_id'], expiration_days=data['expiration_days'], usage_limit=data['usage_limit'])
#     return jsonify(results), 200

# @app.route('/<Matiere>/<Courseid>', methods=['GET'])
# # # @token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
# def Course(Matiere,Courseid) :
#     result = controllers['matiere'].get_Course(Matiere,Courseid)
#     return jsonify(result), 200