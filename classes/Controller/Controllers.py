from datetime import datetime, timedelta
import bcrypt
import jwt
from dotenv import load_dotenv
import os
from bson import ObjectId
import random
import string
from datetime import datetime, timedelta
from classes.Controller.subject import Subject
from threading import Lock
from abc import ABC, abstractmethod
from classes.Controller.observer import Observer

# Charger les variables depuis le fichier .env
load_dotenv()

# Récupérer les clés secrètes
SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")

refresh_tokens_store = {}  # Stocker les refresh tokens en mémoire (à adapter avec une base)
class BaseController(Subject, ABC):
    """Classe de base pour les contrôleurs avec Singleton et gestion MongoDB."""
    _instance = None
    _lock = Lock()

    def __new__(cls, db_connection, *args, **kwargs):
        """Singleton thread-safe."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_connection, collection_name):
        """Initialisation du contrôleur."""
        if not hasattr(self, '_initialized'):
            super().__init__()
            self.collection = db_connection.get_collection(collection_name)
            self._observers = []  # Liste des observateurs
            self._initialized = True

    def add_observer(self, observer: Observer):
        """Ajoute un observateur."""
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: Observer):
        """Supprime un observateur."""
        if observer in self._observers:
            self._observers.remove(observer)

    def notify_observers(self, message: str):
        """Notifie tous les observateurs."""
        for observer in self._observers:
            observer.update(message)

    def add(self, document):
        """Ajoute un document à la collection."""
        if isinstance(document, list):
            self.collection.insert_many(document)
        else:
            self.collection.insert_one(document)
        self.notify_observers(f"{self.__class__.__name__}: ajout effectué.")

    def delete(self, document_id):
        """Supprime un document par son ID."""
        if isinstance(document_id, str):
            document_id = ObjectId(document_id)
        self.collection.delete_one({"_id": document_id})
        self.notify_observers(f"{self.__class__.__name__}: suppression effectuée.")

    def update(self, document_id, updated_data):
        """Met à jour un document par son ID."""
        if isinstance(document_id, str):
            document_id = ObjectId(document_id)
        self.collection.update_one({"_id": document_id}, {"$set": updated_data})
        self.notify_observers(f"{self.__class__.__name__}: mise à jour effectuée.")

    def get_all(self):
        """Récupère tous les documents de la collection."""
        documents = self.collection.find()
        return [self._convert_object_id(doc) for doc in documents]

    def _convert_object_id(self, doc):
        """Convertit l'ObjectId en string."""
        doc['_id'] = str(doc['_id'])
        return doc

    @abstractmethod
    def search(self, **kwargs):
        """Méthode de recherche à implémenter par les classes enfants."""
        pass


class UserController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "users")

    def add(self, document):
        """Ajoute un utilisateur en hachant son mot de passe."""
        if isinstance(document, list):
            for doc in document:
                doc['password'] = self._hash_password(doc['password'])
        else:
            document['password'] = self._hash_password(document['password'])

        super().add(document)

    def _hash_password(self, password):
        """Hache le mot de passe avec bcrypt."""
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')

    def search(self, **kwargs):
        users_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(user['_id']),
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'password': user['password'],
                'role_id': str(user['role_id'])
            }
            for user in users_data
        ]


    def authenticate(self, email, password):
        """Authentifie un utilisateur et renvoie les tokens JWT."""
        user = self.collection.find_one({'email': email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Générer les tokens JWT
            access_token = self._generate_access_token(user['_id'],user['first_name'],user['last_name'],user['email'],user['password'],user['role_id'])
            refresh_token = self._generate_refresh_token(user['_id'], user['role_id'])

            user['access_token'] = access_token
            user['refresh_token'] = refresh_token
            # Stocker le refresh token
            refresh_tokens_store[str(user['_id']), str(user['role_id'])] = refresh_token
            return {
                'message': 'Connexion réussie',
                'access_token': access_token,
                'refresh_token': refresh_token
            }

        return {'error': 'Email ou mot de passe incorrect'}


    def _generate_access_token(self, user_id,first_name,last_name,email,password,role_id):
            """Génère un token JWT valide pendant 24 heure."""
            payload = {
                'user_id': str(user_id),
                'first_name': str(first_name),
                'last_name': str(last_name),
                'email': str(email),
                'password': str(password),
                'role_id': str(role_id),
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def _generate_refresh_token(self, user_id, role_id, expires_in=7):
        """Génère un refresh token valide pour 7 jours."""
        payload = {
            'user_id': str(user_id),
            'role_id': str(role_id),
            'exp': datetime.utcnow() + timedelta(days=expires_in)
        }
        return jwt.encode( payload,REFRESH_SECRET_KEY, algorithm='HS256')


    def refresh_access_token(self, refresh_token):
        """Rafraîchit l'access token avec un refresh token valide."""
        try:
            # Décodage du refresh token
            payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            role_id = payload['role_id']

            # Vérifier si le refresh token est valide
            stored_token = refresh_tokens_store.get((user_id, role_id))
            if stored_token != refresh_token:
                return {'error': 'Refresh token invalide'}, 401

            # Générer un nouveau access token avec les informations nécessaires
            user = self.collection.find_one({'_id': ObjectId(user_id)})
            if not user:
                return {'error': 'Utilisateur introuvable'}, 404

            new_access_token = self._generate_access_token(
                user['_id'], user['first_name'], user['last_name'],
                user['email'], user['password'], user['role_id']
            )
            return {'access_token': new_access_token}, 200

        except jwt.ExpiredSignatureError:
            return {'error': 'Refresh token expiré'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Refresh token invalide'}, 401

    def verify_token(self, token):
        """Vérifie si le token JWT est valide et renvoie les informations utilisateur."""
        try:
            # Décodage du token JWT
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # Vérifier si l'utilisateur existe toujours
            user = self.collection.find_one({'_id': ObjectId(payload['user_id'])})
            if not user:
                return {'valid': False, 'error': 'Utilisateur introuvable'}

            return {'valid': True, 'user_id': str(user['_id']), 'role_id': str(user['role_id'])}

        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expiré'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'error': 'Token invalide'}

class EtudiantController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "etudiants")

    def search(self, **kwargs):
        etudiants_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(etudiant['_id']),
                'nom': etudiant['nom'],
                'prenom': etudiant['prenom'],
                'date_naissance': etudiant['date_naissance'],
                'telephone': etudiant['telephone'],
                'telephone_pere': etudiant['telephone_pere'],
                'niveau_scholaire': etudiant['niveau_scholaire'],
                'annee_scholaire': etudiant['annee_scholaire'],
                'code_de_barre': etudiant['code_de_barre']
            }
            for etudiant in etudiants_data
        ]
    

class EnseignantsController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "enseignants")

    def search(self, **kwargs):
        enseignants_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(enseignant['_id']),
                'nom': enseignant['nom'],
                'prenom': enseignant['prenom'],
                'telephone': enseignant['telephone'],
                'code_barre': enseignant['code_barre'],
                'niveau_academique': enseignant['niveau_academique']
            }
            for enseignant in enseignants_data
        ]
    

class RoleController(BaseController):
     def __init__(self, db_connection):
         super().__init__(db_connection, "roles")

     def search(self, **kwargs):
         roles_data = self.collection.find(kwargs)
         return [
             {'_id': str(role['_id']), 'role_name': role['role_name']}
             for role in roles_data
         ]


# class AuditLogController(BaseController):
#     def __init__(self, db_connection):
#         super().__init__(db_connection, "audit_logs")

#     def search(self, **kwargs):
#         logs_data = self.collection.find(kwargs)
#         return [
#         {
#             '_id': str(log['_id']),
#             'user': log['user'],
#             'action': log['action'],
#             'timestamp': log['timestamp']
#         }
#         for log in logs_data
#     ]


class MatieresManager(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "matieres")
        self.db = db_connection
        self.collection = db_connection.get_collection("codes_acces")

    def generate_code(self, matiere_id=None, chapitre_id=None, expiration_days=7, usage_limit=1):
        """
        Génère un code d'accès pour une matière ou un chapitre.
        """
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        expiration_date = datetime.now() + timedelta(days=expiration_days)

        self.codes_collection.insert_one({
            "code": code,
            "matiere_id": str(matiere_id) if matiere_id else None,
            "chapitre_id": str(chapitre_id) if chapitre_id else None,
            "expiration_date": expiration_date,
            "usage_limit": usage_limit,
            "used_count": 0
        })

        return code

    def validate_code(self, code, etudiant_id):
        """
        Valide et utilise un code d'accès pour inscrire un étudiant.
        """
        code_data = self.codes_collection.find_one({"code": code})
        if not code_data:
            return {'error': 'Code invalide'}, 404

        if code_data['expiration_date'] < datetime.now():
            return {'error': 'Code expiré'}, 403

        if code_data['used_count'] >= code_data['usage_limit']:
            return {'error': 'Code déjà utilisé au maximum'}, 403

        if code_data['matiere_id']:
            self.add_etudiant_to_matiere(code_data['matiere_id'], etudiant_id)
        elif code_data['chapitre_id']:
            self.add_etudiant_to_chapitre(code_data['matiere_id'], code_data['chapitre_id'], etudiant_id)

        # Mise à jour de l'utilisation du code
        code_data['used_count'] += 1
        if code_data['used_count'] >= code_data['usage_limit']:
            self.codes_collection.delete_one({"_id": code_data["_id"]})
        else:
            self.codes_collection.update_one(
                {"_id": code_data["_id"]},
                {"$set": {"used_count": code_data['used_count']}}
            )
        return {'message': 'Code utilisé avec succès'}, 200

    def add(self, document):
        """
        Ajoute une matière à la collection.
        """
        existing_matiere = self.matieres_collection.find_one({
            'nomMatiere': document['nomMatiere'],
            'enseignant': document['enseignant']
        })

        if existing_matiere:
            existing_etudiants = set(existing_matiere.get('etudiants', []))
            new_etudiants = set(document.get('etudiants', []))
            etudiants_to_add = new_etudiants - existing_etudiants

            if etudiants_to_add:
                self.matieres_collection.update_one(
                    {"_id": existing_matiere["_id"]},
                    {"$push": {"etudiants": {"$each": list(etudiants_to_add)}}}
                )
        else:
            document['chapitres'] = []  # Initialiser les chapitres
            self.matieres_collection.insert_one(document)

    def add_chapitre(self, matiere_id, chapitre):
        """
        Ajoute un chapitre à une matière.
        """
        matiere = self.matieres_collection.find_one({"_id": ObjectId(matiere_id)})
        if not matiere:
            return {'error': 'Matière introuvable'}, 404

        chapitre['_id'] = str(ObjectId())  # Générer un ID unique pour le chapitre
        chapitre['classe'] = chapitre.get('classe', [])  # Initialiser la classe
        self.matieres_collection.update_one(
            {"_id": ObjectId(matiere_id)},
            {"$push": {"chapitres": chapitre}}
        )
        return {'message': 'Chapitre ajouté à la matière'}, 200

    def get_Course (self,matiere_id, chapitre_id) : 
        matiere = self.matieres_collection.find_one({"name": ObjectId(matiere_id)})
        if not matiere:
            return {'error': 'Matière introuvable'}, 404
        else :
            chapitre = self.matieres_collection.find_one({"_id": ObjectId(chapitre_id)})
            return chapitre
        
    def add_etudiant_to_matiere(self, matiere_id, etudiant_id):
        """
        Ajoute un étudiant à une matière.
        """
        matiere = self.matieres_collection.find_one({"_id": ObjectId(matiere_id)})
        if not matiere:
            return {'error': 'Matière introuvable'}, 404

        if etudiant_id not in matiere.get('etudiants', []):
            self.matieres_collection.update_one(
                {"_id": ObjectId(matiere_id)},
                {"$push": {"etudiants": etudiant_id}}
            )
        return {'message': 'Étudiant ajouté à la matière'}, 200

    def add_etudiant_to_chapitre(self, matiere_id, chapitre_id, etudiant_id):
        """
        Ajoute un étudiant à un chapitre spécifique.
        """
        matiere = self.matieres_collection.find_one({"_id": ObjectId(matiere_id)})
        if not matiere:
            return {'error': 'Matière introuvable'}, 404

        chapitre = next((c for c in matiere['chapitres'] if c['_id'] == chapitre_id), None)
        if not chapitre:
            return {'error': 'Chapitre introuvable'}, 404

        if etudiant_id not in chapitre.get('classe', []):
            self.matieres_collection.update_one(
                {"_id": ObjectId(matiere_id), "chapitres._id": chapitre_id},
                {"$push": {"chapitres.$.classe": etudiant_id}}
            )
            return {'message': 'Étudiant ajouté au chapitre'}, 200
        else:
            return {'error': 'Étudiant déjà dans le chapitre'}, 400

    def search(self, **kwargs):
        matieres = self.collection.find(kwargs)
        return [
        {
            '_id': str(matieres['_id']),
            # le reste de la recherche !
        }
        for matiere in matieres
    ]