from pymongo import MongoClient
from threading import Lock

class MongoDBConnection:
    """Singleton pour gérer la connexion MongoDB."""
    _instance = None
    _lock = Lock()

    def __new__(cls, uri, db_name):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(MongoDBConnection, cls).__new__(cls)
                cls._instance.client = MongoClient(uri)
                cls._instance.db = cls._instance.client[db_name]
        return cls._instance

    def get_collection(self, collection_name):
        """Récupère une collection de la base de données."""
        return self.db[collection_name]


