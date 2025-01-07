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


class EtudiantController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "etudiants")

    def add(self, document):
        """Ajoute un étudiant en hachant son mot de passe."""
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
        etudiants_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(etudiant['_id']),
                'nom': etudiant.get('nom'),
                'prenom': etudiant.get('prenom'),
                'telephone': etudiant.get('telephone'),
                'telephonePere': etudiant.get('telephonePere'),
                'photo': etudiant.get('photo'),
            }
            for etudiant in etudiants_data
        ]

    def authenticate(self, email, password):
        """Authentifie un étudiant et renvoie les tokens JWT."""
        etudiant = self.collection.find_one({'email': email})

        if etudiant and bcrypt.checkpw(password.encode('utf-8'), etudiant['password'].encode('utf-8')):
            # Générer les tokens JWT
            access_token = self._generate_access_token(etudiant['_id'], etudiant.get('nom'), etudiant.get('prenom'), etudiant.get('email'), etudiant.get('password'), etudiant.get('telephone'))
            refresh_token = self._generate_refresh_token(etudiant['_id'], etudiant.get('telephone'))

            etudiant['access_token'] = access_token
            etudiant['refresh_token'] = refresh_token
            # Stocker le refresh token
            refresh_tokens_store[str(etudiant['_id']), str(etudiant.get('telephone'))] = refresh_token
            return {
                'message': 'Connexion réussie',
                'access_token': access_token,
                'refresh_token': refresh_token
            }

        return {'error': 'Email ou mot de passe incorrect'}

    def _generate_access_token(self, etudiant_id, nom, prenom, email, password, telephone):
        """Génère un token JWT valide pendant 24 heures."""
        payload = {
            'etudiant_id': str(etudiant_id),
            'nom': nom,
            'prenom': prenom,
            'email': email,
            'password': password,
            'telephone': telephone,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    def _generate_refresh_token(self, etudiant_id, telephone, expires_in=7):
        """Génère un refresh token valide pour 7 jours."""
        payload = {
            'etudiant_id': str(etudiant_id),
            'telephone': telephone,
            'exp': datetime.utcnow() + timedelta(days=expires_in)
        }
        return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')

    def refresh_access_token(self, refresh_token):
        """Rafraîchit l'access token avec un refresh token valide."""
        try:
            # Décodage du refresh token
            payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=['HS256'])
            etudiant_id = payload['etudiant_id']
            telephone = payload['telephone']

            # Vérifier si le refresh token est valide
            stored_token = refresh_tokens_store.get((etudiant_id, telephone))
            if stored_token != refresh_token:
                return {'error': 'Refresh token invalide'}, 401

            # Générer un nouveau access token avec les informations nécessaires
            etudiant = self.collection.find_one({'_id': ObjectId(etudiant_id)})
            if not etudiant:
                return {'error': 'Étudiant introuvable'}, 404

            new_access_token = self._generate_access_token(
                etudiant['_id'], etudiant.get('nom'), etudiant.get('prenom'),
                etudiant.get('email'), etudiant.get('password'), etudiant.get('telephone')
            )
            return {'access_token': new_access_token}, 200

        except jwt.ExpiredSignatureError:
            return {'error': 'Refresh token expiré'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Refresh token invalide'}, 401

    def verify_token(self, token):
        """Vérifie si le token JWT est valide et renvoie les informations de l'étudiant."""
        try:
            # Décodage du token JWT
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # Vérifier si l'étudiant existe toujours
            etudiant = self.collection.find_one({'_id': ObjectId(payload['etudiant_id'])})
            if not etudiant:
                return {'valid': False, 'error': 'Étudiant introuvable'}

            return {'valid': True, 'etudiant_id': str(etudiant['_id']), 'telephone': etudiant.get('telephone')}

        except jwt.ExpiredSignatureError:
            return {'valid': False, 'error': 'Token expiré'}
        except jwt.InvalidTokenError:
            return {'valid': False, 'error': 'Token invalide'}


class EnseignantsController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "enseignants")

    def search(self, **kwargs):
        enseignants_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(enseignant['_id']),
                'nom': enseignant.get('nom'),
                'prenom': enseignant.get('prenom'),
                'telephone': enseignant.get('telephone'),
                'niveauAcademique': enseignant.get('niveauAcademique')
            }
            for enseignant in enseignants_data
        ]
    def add(self, document):
        super().add(document)

    def delete(self, document_id):
        super().delete(document_id)

    def update(self, document_id, updated_data):
        super().update(document_id, updated_data)

class TestemonialController(BaseController):

    def __init__(self, db_connection):
        super().__init__(db_connection, "testemonial")

    def search(self, **kwargs):
        testemonial_data = self.collection.find(kwargs)
        return [
            {
                '_id': str(test['_id']),
                'nom': test.get('nom'),
                'prenom': test.get('prenom'),
                'description': test.get('description'),
                'videoPath': test.get('videoPath'),
            }
            for test in testemonial_data
        ]
    def add(self, document):
        super().add(document)

    def delete(self, document_id):
        super().delete(document_id)

    def update(self, document_id, updated_data):
        super().update(document_id, updated_data)


class CoursController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "cours")

    def search(self, **kwargs):
        cours_data = self.collection.find(kwargs)
        result = []
        for cours in cours_data:
            etudiants_list = []
            for etudiant_id in cours.get('etudiants', []):
                etudiant = self.collection.database['etudiants'].find_one({"_id": ObjectId(etudiant_id)})
                if etudiant:
                    etudiants_list.append({
                        '_id': str(etudiant['_id']),
                        'nom': etudiant.get('nom'),
                        'prenom': etudiant.get('prenom'),
                        'telephone': etudiant.get('telephone'),
                        'telephonePere': etudiant.get('telephonePere'),
                        'photo': etudiant.get('photo')
                    })
            result.append({
                '_id': str(cours['_id']),
                'nom': cours.get('nom'),
                'description': cours.get('description'),
                'tags': cours.get('tags'),
                'path_video': cours.get('path_video'),
                'etudiants': etudiants_list
            })
        return result

    def add(self, document):
        if 'etudiants' not in document:
            document['etudiants'] = []
        super().add(document)

    def delete(self, document_id):
        super().delete(document_id)

    def update(self, document_id, updated_data):
        super().update(document_id, updated_data)

    def add_etudiant(self, cours_id, etudiant_id):
        if isinstance(cours_id, str):
            cours_id = ObjectId(cours_id)
        if isinstance(etudiant_id, str):
            etudiant_id = ObjectId(etudiant_id)

        # Vérifier si l'étudiant existe
        etudiant = self.collection.database['etudiants'].find_one({"_id": etudiant_id})
        if not etudiant:
            return {'error': 'Étudiant introuvable'}, 404

        self.collection.update_one(
            {"_id": cours_id},
            {"$addToSet": {"etudiants": etudiant_id}}
        )
        return {'message': 'Étudiant ajouté au cours'}, 200

    def remove_etudiant(self, cours_id, etudiant_id):
        if isinstance(cours_id, str):
            cours_id = ObjectId(cours_id)
        self.collection.update_one(
            {"_id": cours_id},
            {"$pull": {"etudiants": ObjectId(etudiant_id)}}
        )


class MatierController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "matiers")

    def search(self, **kwargs):
        matiers_data = self.collection.find(kwargs)
        result = []
        for matier in matiers_data:
            # Populate cours array
            cours_list = []
            for cours_id in matier.get('cours', []):
                cours = self.collection.database['cours'].find_one({"_id": ObjectId(cours_id)})
                if cours:
                    cours_list.append({
                        '_id': str(cours['_id']),
                        'nom': cours.get('nom'),
                        'description': cours.get('description'),
                        'tags': cours.get('tags'),
                        'path_video': cours.get('path_video'),
                        'etudiants': [str(etudiant_id) for etudiant_id in cours.get('etudiants', [])]
                    })
            # Populate etudiants array
            etudiants_list = []
            for etudiant_id in matier.get('etudiants', []):
                etudiant = self.collection.database['etudiants'].find_one({"_id": ObjectId(etudiant_id)})
                if etudiant:
                    etudiants_list.append({
                        '_id': str(etudiant['_id']),
                        'nom': etudiant.get('nom'),
                        'prenom': etudiant.get('prenom'),
                        'telephone': etudiant.get('telephone'),
                        'telephonePere': etudiant.get('telephonePere'),
                        'photo': etudiant.get('photo')
                    })
            # Populate enseignant
            enseignant = self.collection.database['enseignants'].find_one({"_id": ObjectId(matier.get('enseignant'))})
            enseignant_info = {
                '_id': str(enseignant['_id']),
                'nom': enseignant.get('nom'),
                'prenom': enseignant.get('prenom'),
                'telephone': enseignant.get('telephone'),
                'codeBarre': enseignant.get('codeBarre'),
                'niveauAcademique': enseignant.get('niveauAcademique')
            } if enseignant else None
            result.append({
                '_id': str(matier['_id']),
                'nom': matier.get('nom'),
                'enseignant': enseignant_info,
                'cours': cours_list,
                'etudiants': etudiants_list
            })
        return result

    def add(self, document):
        cours_ids = document.get('cours', [])
        for cours_id in cours_ids:
            if not self.collection.database['cours'].find_one({"_id": ObjectId(cours_id)}):
                return {'error': f'Cours avec ID {cours_id} introuvable'}, 404
        super().add(document)

    def delete(self, document_id):
        super().delete(document_id)

    def update(self, document_id, updated_data):
        super().update(document_id, updated_data)

    def add_cours(self, matier_id, cours_id):
        if isinstance(matier_id, str):
            matier_id = ObjectId(matier_id)
        self.collection.update_one(
            {"_id": matier_id},
            {"$addToSet": {"cours": cours_id}}
        )
        # Vérifier si le cours existe
        cours = self.collection.database['cours'].find_one({"_id": ObjectId(cours_id)})
        if not cours:
            return {'error': 'Cours introuvable'}, 404
        return {'message': 'Cours ajouté à la matière'}, 200

    def remove_cours(self, matier_id, cours_id):
        if isinstance(matier_id, str):
            matier_id = ObjectId(matier_id)
        self.collection.update_one(
            {"_id": matier_id},
            {"$pull": {"cours": ObjectId(cours_id)}}
        )

    def add_etudiant(self, matier_id, etudiant_id):
        if isinstance(matier_id, str):
            matier_id = ObjectId(matier_id)

        etudiant = self.collection.database['etudiants'].find_one({"_id":ObjectId( etudiant_id)})
        if not etudiant:
            return {'error': 'Étudiant introuvable'}, 404

        self.collection.update_one(
            {"_id": matier_id},
            {"$addToSet": {"etudiants": etudiant_id}}
        )
        return {'message': 'Étudiant ajouté à la matière'}, 200

    def remove_etudiant(self, matier_id, etudiant_id):
        if isinstance(matier_id, str):
            matier_id = ObjectId(matier_id)
        self.collection.update_one(
            {"_id": matier_id},
            {"$pull": {"etudiants": ObjectId(etudiant_id)}}
        )
