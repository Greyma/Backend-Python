from abc import ABC, abstractmethod
from threading import Lock  # Pour gérer la sécurité des threads si nécessaire

class Observer(ABC):
    """Interface de base pour l'observateur."""
    @abstractmethod
    def update(self, has_changed: bool, message: str):
        """Mise à jour avec état du changement et message."""
        pass

class ConcreteObserver(Observer):
    """Observateur concret avec Singleton."""
    _instance = None  # Variable de classe pour stocker l'instance unique
    _lock = Lock()     # Pour gérer l'accès en environnement multi-threadé

    def __new__(cls, *args, **kwargs):
        """Implémentation du Singleton avec verrouillage pour thread safety."""
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ConcreteObserver, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialisation de l'observateur."""
        self._has_changed = False 
        self._message = ""  

    # Setter pour has_changed
    def set_has_changed(self, value: bool):
        if isinstance(value, bool):
            self._has_changed = value
        else:
            raise ValueError("has_changed doit être de type booléen.")

    # Getter pour has_changed
    def get_has_changed(self) -> bool:
        return self._has_changed

    def update(self, message: str):
        self.set_has_changed(True)
        self._message = message

        if self._has_changed:
            print(f"[Notification] {self._message}")
