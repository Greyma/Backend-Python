from abc import ABC, abstractmethod

class Subject(ABC):
    """Interface pour le sujet (observable)."""

    @abstractmethod
    def add_observer(self, observer):
        """Ajoute un observateur."""
        pass

    @abstractmethod
    def remove_observer(self, observer):
        """Supprime un observateur."""
        pass

    @abstractmethod
    def notify_observers(self, message: str):
        """Notifie tous les observateurs."""
        pass
