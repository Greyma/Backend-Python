from flask import Flask, jsonify, request
from Mongodb_class.Mongo_connect import MongoDBConnection
from flask import Flask, request, jsonify
from functools import wraps
from jwt import decode, ExpiredSignatureError, InvalidTokenError
from pymongo.errors import ConfigurationError
import jwt
from dotenv import load_dotenv
import openai
from classes.Controller.observer import ConcreteObserver
from flask_cors import CORS
import os
from classes.Controller.Controllers import (
    RoleController, UserController, AuditLogController, BudgetController,
    CategoryController, PeriodController, NotificationController, 
    )

load_dotenv()
SECRET_KEY =  os.getenv("SECRET_KEY")
uri = os.getenv("uri")
db_name = os.getenv("db_name")

# Charger les variables depuis le fichier .env
load_dotenv()

# Récupérer les clés secrètes
API_KEYS_Generative = os.getenv("API_KEYS_Generative")


app = Flask(__name__)
CORS(app)
db_connection = MongoDBConnection(uri, db_name)


controllers = {
    "role": RoleController(db_connection),
    "user": UserController(db_connection),
    "audit": AuditLogController(db_connection),
    "budget": BudgetController(db_connection),
    "category": CategoryController(db_connection),
    "period": PeriodController(db_connection),
    "notif": NotificationController(db_connection)
}

controllers_classes = [
    RoleController, UserController, AuditLogController, BudgetController,
    CategoryController, PeriodController, NotificationController
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

def search_items(controller_name):
    criteria = request.args.to_dict()
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
@token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def delete(controller_name, item_id):
    return delete_item(controller_name, item_id)

@app.route('/<controller_name>/<item_id>', methods=['PUT'])
@token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def update(controller_name, item_id):
    return update_item(controller_name, item_id)

@app.route('/<controller_name>', methods=['GET'])
@token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def get_all(controller_name):
    return get_all_items(controller_name)

@app.route('/<controller_name>/search', methods=['GET'])
@token_required(['admin', '671420c2df2d71de25efde15', 'viewer'])
def search(controller_name):
    return search_items(controller_name)


@app.route('/login',methods=['POST'])
def authentificate(): 
    data = request.json
    token = controllers['user'].authenticate(data['email'],data['password'])
    return token



# Exécution de l'application
if __name__ == '__main__':
    app.run(debug=False)
