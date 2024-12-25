# Fintech Backend API Documentation

### **Base URL**
> [https://fintech-backend-ltm6.onrender.com](https://fintech-backend-ltm6.onrender.com)

---

## **Table des Contenus**
- [Introduction](#introduction)
- [Méthodes Disponibles](#méthodes-disponibles)
  - [GET](#get)
  - [POST](#post)
  - [PUT](#put)
  - [DELETE](#delete)
  - [Recherche](#recherche)
- [Design Patterns Utilisés](#design-patterns-utilisés)

---

## **Introduction**
Ce backend a été conçu pour une application Fintech et expose plusieurs **endpoints REST** permettant de gérer différentes entités comme des revenus, utilisateurs, rapports, projets, notifications, et plus encore. Le système est pensé pour une **gestion optimisée de la mémoire** et permet une **détection en temps réel** des événements grâce à une architecture robuste basée sur plusieurs **design patterns**.

---

## **Méthodes Disponibles**

### **GET**  
Cette méthode permet de récupérer des données à partir de différentes entités.

- **Endpoints :**
  - `/revenue`
  - `/report`
  - `/role`
  - `/user`
  - `/audit`
  - `/budget`
  - `/category`
  - `/period`
  - `/notif`
  - `/expense`
  - `/kpi`
  - `/project`

---

### **POST**  
Cette méthode permet d’ajouter une nouvelle entité.

- **Format :**
  ```
  POST /<name>
  ```

- **Exemple :**
  ```
  POST /user
  ```

---

### **PUT**  
Cette méthode permet de modifier une entité existante en fournissant son ID.

- **Format :**
  ```
  PUT /<name>/id
  ```

- **Exemple :**
  ```
  PUT /user/1
  ```

---

### **DELETE**  
Cette méthode permet de supprimer une entité existante en fournissant son ID.

- **Format :**
  ```
  DELETE /<name>/id
  ```

- **Exemple :**
  ```
  DELETE /user/1
  ```

---

### **Recherche**  

#### **Recherche Simple**  
Cette méthode permet de rechercher une entité à l’aide de **paramètres spécifiques**.

- **Format :**
  ```
  GET /<name>/search?ism_la_colonne=valeur_voulu
  ```

- **Exemple :**
  ```
  GET /user/search?email=example@email.com
  ```

#### **Recherche avec Plusieurs Paramètres**  
Utilisez l’opérateur `&` pour passer plusieurs critères de recherche.

- **Format :**
  ```
  GET /<name>/search?ism_la_colonne=valeur_voulu&ism_la_colonne2=valeur_voulu2
  ```

- **Exemple :**
  ```
  GET /user/search?email=example@email.com&status=active
  ```

---

## **Design Patterns Utilisés**
Ce backend est construit sur la base de plusieurs **design patterns** pour garantir une **architecture efficace, flexible** et capable de répondre aux besoins en temps réel.

1. **Singleton**  
   - Utilisé pour la **gestion de la mémoire du serveur** en instanciant une seule fois certains composants critiques du système.
   - Assure qu'une seule instance de certains objets est utilisée dans toute l'application.

2. **Composite**  
   - Permet une **flexibilité du code** en structurant les entités sous forme d’arborescences, ce qui facilite leur gestion en tant qu’objets composites ou unités individuelles.

3. **Observer**  
   - Implémenté pour **détecter les changements** en temps réel et réagir immédiatement à ces événements.
   - Garantit une **réactivité optimale** du système face aux événements et actions de l’utilisateur ou du serveur.

---

## **Installation et Configuration**
1. **Cloner le dépôt :**
   ```bash
   git clone <url-du-depot>
   ```
2. **Installer les dépendances :**
   ```bash
   pip install -r requirements.txt
   ```
3. **Démarrer le serveur :**
   ```bash
   gunicorn -w 4 app:app
   ```

---

## **Conclusion**
Ce backend permet une **gestion complète** des entités nécessaires à une application Fintech. Avec son architecture basée sur des **design patterns**, il garantit une **performance optimale** et une **réactivité en temps réel**.