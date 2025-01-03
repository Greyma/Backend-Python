from flask import Flask, jsonify, request
from Mongodb_class.Mongo_connect import MongoDBConnection
from flask import Flask, request, jsonify
from functools import wraps
from jwt import decode, ExpiredSignatureError, InvalidTokenError
from dotenv import load_dotenv
from classes.Controller.observer import ConcreteObserver
from flask_cors import CORS
import os
from classes.Controller.Controllers import (
 UserController, EtudiantController ,EnseignantsController ,MatieresManager
    )


load_dotenv()
SECRET_KEY =  os.getenv("SECRET_KEY")
uri = os.getenv("uri")
db_name = os.getenv("db_name")
API_KEYS_Generative = os.getenv("API_KEYS_Generative")

app = Flask(__name__)
CORS(app)
db_connection = MongoDBConnection(uri, db_name)

controllers = {
    "user": UserController(db_connection),
    "etudiants": EtudiantController(db_connection),
    "enseignants": EnseignantsController(db_connection),
    "matiere" : MatieresManager(db_connection)

}

controllers_classes = [
     UserController,EtudiantController,EnseignantsController,MatieresManager

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
    token = controllers['user'].authenticate(data['email'],data['password'])
    return token


@app.route('/addmatiere',methods=['POST']) 
def addmatiere() : 
    data = request.json
    controllers['matiere'].add(data)
    return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

@app.route('/addchapitre',methods=['POST']) 
def chapitre() : 
    data = request.json
    controllers['matiere'].add_chapitre(data)
    return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

@app.route('/to_chapitre',methods=['POST']) 
def to_chapitre() : 
    data = request.json
    controllers['matiere'].add_etudiant_to_chapitre(data)
    return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

@app.route('/to_matiere',methods=['POST']) 
def to_matiere() : 
    data = request.json
    controllers['matiere'].add_etudiant_to_matiere(data)
    return jsonify({"message": f"{controllers['matiere'].capitalize()} ajouté avec succès"}), 201

@app.route('/generateCode',methods=['POST']) 
def generateCode() :
    data = request.json
    results = controllers['matiere'].generate_code(matiere_id=data['matiere_id'], chapitre_id=data['chapitre_id'], expiration_days=data['expiration_days'], usage_limit=data['usage_limit'])   
    return jsonify(results), 200

@app.route('/<Matiere>/<Courseid>', methods=['GET'])
# # @token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def Course(Matiere,Courseid) :
    result = controllers['matiere'].get_Course(Matiere,Courseid)
    return jsonify(result), 200

# Exécution de l'application
if __name__ == '__main__':
    app.run(debug=True )
