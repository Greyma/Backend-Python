from datetime import datetime, timedelta
import bcrypt
import jwt
from dotenv import load_dotenv
import os
from bson import ObjectId
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
                'access_token': access_token
                #'refresh_token': refresh_token
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
        return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256')


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


class RoleController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "roles")
    
    def search(self, **kwargs):
        roles_data = self.collection.find(kwargs)
        return [
            {'_id': str(role['_id']), 'role_name': role['role_name']}
            for role in roles_data
        ]


class BudgetController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "budgets")

    def search(self, **kwargs):
        budgets_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(budget['_id']),
            'allocated_budget': budget['allocated_budget'],
            'fiscal_year': budget['fiscal_year'],
            'department': budget['department'],
            'spent_budget': budget['spent_budget'],
            'remaining_budget': budget['remaining_budget'],
            'description': budget['description']
        }
        for budget in budgets_data
    ]

class AuditLogController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "audit_logs")

    def search(self, **kwargs):
        logs_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(log['_id']),
            'user': log['user'],
            'action': log['action'],
            'timestamp': log['timestamp']
        }
        for log in logs_data
    ]

class AssetController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "assets")

    def search(self, **kwargs):
        assets_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(asset['_id']),
            'asset_name': asset['asset_name'],
            'asset_value': asset['asset_value'],
            'asset_name': asset['asset_name'],
            'date': asset['date'],
            'description': asset['description']
        }
        for asset in assets_data
    ]

class CategoryController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "categories")

    def search(self, **kwargs):
        categories_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(category['_id']),
            'category_name': category['category_name']
        }
        for category in categories_data
    ]

class PeriodController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "periods")

    def search(self, **kwargs):
        periods_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(period['_id']),
            'start_date': period['start_date'],
            'end_date': period['end_date']
        }
        for period in periods_data
    ]


class DeptController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "depts")

    def search(self, **kwargs):
        depts_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(dept['_id']),
            'debt_type': dept['debt_type'],
            'principal': dept['principal'],
            'maturity_date': dept['maturity_date'],
            'payment_due_date': dept['payment_due_date'],
            'amount_paid': dept['amount_paid'],
            'outstanding_balance': dept['outstanding_balance'],
            'description': dept['description']
        }
        for dept in depts_data
    ]

class NotificationController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "notifications")


    def search(self, **kwargs):
        notifications_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(notification['_id']),
            'user': notification['user'],
            'message': notification['message'],
            'status': notification['status'],
            'created_at': notification['created_at']
        }
        for notification in notifications_data
    ]

class ExpenseController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "expenses")

    def search(self, **kwargs):
        expenses_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(expense['_id']),
            'description': expense['description'],
            'amount_expenses': expense['amount_expenses'],
            'date': expense['date'],
            'expense_category': expense['expense_category'],
            'department': expense['department']
        }
        for expense in expenses_data
    ]

class ReportController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "reports")

    def search(self, **kwargs):
        """Recherche des rapports selon les critères donnés."""
        reports_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(report['_id']),
            'report_type': report['report_type'],
            'generated_at': report['generated_at'],
            'period': report['period'],
            'created_by': report['created_by']
        }
        for report in reports_data
    ]

class RevenueController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "revenues")

    def search(self, **kwargs):
        """Recherche des revenus selon les critères donnés."""
        revenues_data = self.collection.find(kwargs)
        return [
                {
                    '_id': str(revenue['_id']),
                    'description': revenue['description'],
                    'amount_revenue': revenue['amount_revenue'],
                    'date': revenue['date'],
                    'product_line': revenue['product_line'],
                    'customer_type': revenue['customer_type']
                }
                for revenue in revenues_data
            ]


class FundingController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "fundings")

    def search(self, **kwargs):
        fundings_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(funding['_id']),
            'funding_round': funding['funding_round'],
            'amount_raised': funding['amount_raised'],
            'date': funding['date'],
            'investor_name': funding['investor_name'],
            'valuation': funding['valuation'],
            'description': funding['description']
        }
        for funding in fundings_data
    ]

class CashController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "Cashs")

    def search(self, **kwargs):
        fundings_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(funding['_id']),
            'cash_inflow': funding['cash_inflow'],
            'cash_outflow': funding['cash_outflow'],
            'date': funding['date'],
            'net_cash_flow': funding['net_cash_flow'],
            'category': funding['category'],
            'description': funding['description']
        }
        for funding in fundings_data
    ]

class KPIController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "kpis")

    def search(self, **kwargs):
        kpis_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(kpi['_id']),
            'name': kpi['name'],
            'value': kpi['value'],
            'date': kpi['date']
        }
        for kpi in kpis_data
    ]
class ProjectController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "projects")

    def search(self, **kwargs):
        projects_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(project['_id']),
            'project_name': project['project_name'],
            'start_date': project['start_date'],
            'end_date': project['end_date'],
            'created_by': project['created_by']
        }
        for project in projects_data
    ]

class ProfitController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "profits")

    def search(self, **kwargs):
        profits_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(profit['_id']),
            'date': profit['date'],
            'revenue': profit['revenue'],
            'expenses': profit['expenses'],
            'net_profit': profit['net_profit'],
            'profit_margin': profit['profit_margin'],
            'description': profit['description']
        }
        for profit in profits_data
    ]

class InvestController(BaseController):
    def __init__(self, db_connection):
        super().__init__(db_connection, "invests")

    def search(self, **kwargs):
        invests_data = self.collection.find(kwargs)
        return [
        {
            '_id': str(invest['_id']),
            'date': invest['date'],
            'investment_type': invest['investment_type'],
            'investment_amount': invest['investment_amount'],
            'returns': invest['returns'],
            'risk_level': invest['risk_level'],
            'current_value': invest['current_value'],
            'description': invest['description']
        }
        for invest in invests_data
    ]