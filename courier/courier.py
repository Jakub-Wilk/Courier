# Import potrzebnych elementów biblioteki Flask i rozszerzeń Flask Restful i Flask PyMongo

from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
from flask_pymongo import PyMongo

# Import algorytmów kodujących i hashujących

import bcrypt
from hashlib import sha256, shake_256
from base64 import urlsafe_b64encode

# Import pozostałych bibliotek

from datetime import datetime

# Import tajnych danych (URI bazy MongoDB - zawiera ono nazwę użytkownika, hasło, nazwę bazy)

from env import mongo_uri



# Inicjalizacja aplikacji

app = Flask(__name__)
app.config["MONGO_URI"] = mongo_uri
api = Api(app)
mongo = PyMongo(app)



class Auth(Resource):
    """
        Klasa zawierająca funkcje związane z autentyfikacją użytkownika.
    """
    auth_parser = reqparse.RequestParser()  # Inicjalizacja parsera argumentów (pozwala na łatwiejsze przetwarzanie argumentów zapytania HTTP)
    auth_parser.add_argument("action")      #  |
    auth_parser.add_argument("username")    #  | Dodawanie argumentów do parsera
    auth_parser.add_argument("password")    #  |
    auth_parser.add_argument("key")         #  |


    @staticmethod  # Metoda statyczna (można ją wykonać bez inicjalizacji obiektu)
    def validate_key(access_key):
        """
            Ta metoda sprawdza czy dany klucz dostępu znajduje się w bazie danych.
            Jeżeli klucz dostępu nie znajduje się w bazie, jest nieprawidłowy, a więc api przerywa zapytanie i zwraca kod HTTP 401: "Unauthorized".
        """
        if mongo.db.auth.find_one({"key": access_key}) is None:  # Jeśli takiego klucza nie ma w bazie
            abort(401, message=f"Access key {access_key} is invalid!") # Zwróć 401: "Unauthorized"
        return 200  #  Używam wartości 200 dlatego, że jest to kod HTTP "OK", co pozwala mi zwrócić później wartość zwrotną tej funkcji jako kod HTTP


    @staticmethod
    def reactivate(access_key):
        """
            Jeżeli podany klucz dostępu istnieje, ta metoda aktualizuje jego ostatnią godziną aktywacji (reaktywuje go).
        """
        if Auth.validate_key(access_key): # Jeśli taki klucz istnieje
            mongo.db.auth.update_one(
                {"key": access_key}, # Dla takiego klucza w bazie
                {"$set": {"date": datetime.now()}} # Ustaw godzinę ostatniej aktywacji na aktualną godzinę
            )
            return 200


    @staticmethod
    def check_if_active(access_key):
        """
            Ta metoda sprawdza, czy klucz dostępu jest aktywny.
            Jeśli nie jest, usuwa go z bazy danych i zwraca kod HTTP 403: "Forbidden".
        """
        if Auth.validate_key(access_key): # Jeśli taki klucz istnieje
            key_data = mongo.db.auth.find_one({"key": access_key}) # Ściągnij informacje o nim z bazy
            delta = datetime.now() - key_data["date"] # Wylicz różnicę czasu pomiędzy aktualną godziną, a ostatnią reaktywacją
            if delta.seconds // 60 >= 10: # Jeżeli minęło ponad 10 minut od ostatniej reaktywacji
                mongo.db.auth.delete_one({"key": access_key}) # Usuń klucz z bazy
                abort(403, message=f"Access key {access_key} has expired!") # Zwróć 403: "Forbidden"
            return 200 # Jeśli nie minęło 10 minut, wszystko jest w porządku.


    @staticmethod
    def check_and_reactivate(access_key):
        """
            Ta metoda to połączenie dwóch poprzednich. 
            Sprawdza, czy dany klucz jest poprawny, a jeśli jest poprawny, reaktywuje go.
        """
        if Auth.check_if_active(access_key):
            return Auth.update_date(access_key)


    @staticmethod
    def get_user_id(access_key):
        """
            Ta metoda zwraca ID użytkownika, dla którego wystawiony był klucz, jeśli klucz jest aktywny.
        """
        if Auth.check_and_reactivate(access_key):
            return mongo.db.auth.find_one({"key": access_key})["user_id"]


    def post(self):
        """
            Ta metoda obsługuje zapytanie HTTP POST na endpoint autoryzacji.
        """
        args = self.auth_parser.parse_args() # Użyj parsera do przeczytania argumentów zapytania przesłanych przez klienta
        action = args["action"]       # |
        username = args["username"]   # | Przypisz zmienne argumentom
        password = args["password"]   # |


        if action == "refresh": # Jeśli zapytanie to prośba o reaktywację klucza
            if args["key"] is None: # Jeśli klucz nie został podany
                abort(401, message="No access key received!") # Zwróć 401: "Unauthorized"
            return Auth.check_and_reactivate(args["key"]) # Sprawdź poprawność klucza i reaktywuj go


        elif action ==  "login": # Jeśli zapytanie to prośba o zalogowanie
            user = mongo.db.users.find_one({"username": username}) # Wyszukaj w bazie użytkownika o podanym nicku
            if user is None: # Jeżeli takiego nie ma
                abort(404, message=f"User {username} doesn't exist!") # Zwróć 404: "Not Found"
            hashed_password = user["password"]
            if bcrypt.checkpw(urlsafe_b64encode(sha256(password.encode("utf-8")).digest()), hashed_password): # Sprawdź, czy przesłane hasło po shashowaniu zgadza się ze shashowanym hasłem z bazy danych.
                key = urlsafe_b64encode(
                    sha256(
                        str(datetime.timestamp(datetime.now())).encode("utf-8")
                    ).digest()
                ).decode("utf-8") # Utwórz nowy, losowy klucz dostępu

                mongo.db.auth.insert_one(
                    {
                        "key": key,
                        "user_id": user["_id"],
                        "date": datetime.now(),
                    }
                ) # Dodaj klucz do bazy danych
                return key # Zwróć ten klucz klientowi


        elif action == "register": # Jeśli zapytanie to prośba o zarejestrowanie użytkownika
            if mongo.db.users.find_one({"username": username}) is not None: # Jeśli taki użytkownik już istnieje
                abort(409, message=f"A user with username {username} already exists!") # Zwróć 409: "Conflict"
            mongo.db.users.insert_one(
                {
                    "username": username,
                    "password": bcrypt.hashpw(
                        urlsafe_b64encode(sha256(password.encode("utf-8")).digest()),
                        bcrypt.gensalt(),
                    ),
                } # Zapisz nazwę użytkownika i shashowane hasło w bazie
            )
            return 200



class Post(Resource):
    """
        Klasa zawierająca funkcje związane z manipulacją postów.
    """
    post_parser = reqparse.RequestParser() # Inicjalizacja parsera
    post_parser.add_argument("_id")
    post_parser.add_argument("content")
    post_parser.add_argument("visibility")
    post_parser.add_argument("key")

    def get_post_from_id(self, post_id):
        """
            Ta metoda wyszukuje dane posta na podstawie jego ID.
        """
        post = mongo.db.posts.find_one({"_id": post_id})
        if post is None: # Sprawdź, czy post o takim ID istnieje
            self.post_doesnt_exist(post_id)
        return post

    def check_if_can_view(self, key, post_id):
        """
            Ta metoda sprawdza czy ten klucz dostępu pozwala na dostęp do tego posta.
        """
        user_id = Auth.get_user_id(key)
        post = self.get_post_from_id(post_id)
        if post["visibility"] == "private": # Jeśli post jest prywatny
            if post["user_id"] == user_id or user_id in User.get_friends_list(post["user_id"]): # Tylko właściciel i jego przyjaciele mogą go widzieć
                return 200
            else: # Jeśli użytkownik nie jest w tej grupie
                abort(401, message=f"User {user_id} is not authorized to view post {post_id}") # Zwróć 401: "Unauthorized"
        else:
            return 200

    def post_doesnt_exist(self, post_id):
        """
            Ta metoda zwraca 404: "Not Found".
            Jest to po prostu skrót, by sobie oszczędzić pisania.
        """
        abort(404, message=f"Post {post_id} doesn't exist!")

    def get(self):
        """
            Ta metoda obsługuje zapytanie HTTP GET na endpoint postów.
            Zapytanie GET na ten endpoint służy do pobierania informacji o poście.
        """
        args = self.post_parser.parse_args() # Użyj parsera do przeczytania argumentów
        post = self.get_post_from_id(args["_id"])
        if self.check_if_can_view(args["key"], args["_id"]): # Jeśli klucz dostępu pozwala na wyświetlenie posta
            return post # Zwróć posta

    def post(self):
        """
            Ta metoda obsługuje zapytanie HTTP POST na endpoint postów.
            Zapytanie POST na ten endpoint służy do tworzenia nowego posta.
        """
        args = self.post_parser.parse_args() # Użyj parsera do przeczytania argumentów
        user_id = Auth.get_user_id(args["key"]) # Zdobądź nazwę użytkownika
        if args["_id"] is None: # Jeśli nie podano żadnego ID posta
            post_id = shake_256(
                str(datetime.timestamp(datetime.now()), encoding="utf-8")
                + str(user_id, encoding="utf-8")
            ).hexdigest(8) # Utwórz nowe losowe ID posta
            if self.post_from_id(post_id): # Jeśli wylosowane ID istnieje (niebotycznie mała szansa)
                abort(409, message=f"Duplicate post ID {post_id}!") # Zwróć 409: "Conflict"
            args.update(
                {
                    "_id": int(
                        post_id,
                        16,
                    ),
                    "user_id": user_id,
                }
            ) # Dodaj ID i właściciela do informacji o poście
            mongo.db.posts.insert_one(args) # Dodaj posta do bazy danych
            return args # Zwróć informacje o utworzonym poście

    def update(self):
        """
            Ta metoda obsługuje zapytanie HTTP UPDATE na endpoint postów.
            Zapytanie UPDATE na ten endpoint służy do aktualizacji istniejącego posta.
        """
        args = self.post_parser.parse_args() # Użyj parsera do przeczytania argumentów
        user_id = Auth.get_user_id(args["key"]) # Zdobądź nazwę użytkownika
        post = self.get_post_from_id(args["_id"])
        if user_id != post["user_id"]: # Jeśli użytkownik nie jest właścicielem
            abort(401, f"User {user_id} not authorized to update post {post['_id']}") # Zwróć 401: "Unauthorized"
        mongo.db.posts.update_one({"_id": post["_id"]}, {"$set": {"content": args["content"], "visibility": args["visibility"]}}) # Zaktualizuj dane posta
        return 200

    def delete(self):
        """
            Ta metoda obsługuje zapytanie HTTP DELETE na endpoint postów.
            Zapytanie DELETE służy do usuwania istniejącego posta.
        """
        args = self.post_parser.parse_args() # Użyj parsera do przeczytania argumentów
        user_id = Auth.get_user_id(args["key"]) # Zdobądź nazwę użytkownika
        post = self.get_post_from_id(args["_id"])
        if user_id != post["_id"]: # Jeśli użytkownik nie jest właścicielem
            abort(401, f"User {user_id} not authorized to delete post {post['_id']}") # Zwróć 401: "Unauthorized"
        mongo.db.posts.delete_one({"_id": post["_id"]}) # Usuń posta
        return 200



class User(Resource):
    """
        Klasa zawierająca funkcje związane z informacjami o użytkownikach.
    """

    user_parser = reqparse.RequestParser() # Inicjalizacja parsera
    user_parser.add_argument("action")
    user_parser.add_argument("_id")
    user_parser.add_argument("name")
    user_parser.add_argument("birthday")
    user_parser.add_argument("gender")
    user_parser.add_argument("key")

    @staticmethod
    def get_user_from_id(user_id):
        """
            Ta metoda wyszukuje dane użytkownika na podstawie jego ID
        """
        user = mongo.db.users.find_one({"_id": user_id})
        if user is None: # Sprawdź, czy post o takim ID istnieje
            User.user_doesnt_exist(user_id)
        return user
    
    @staticmethod
    def user_doesnt_exist(user_id):
        """
            Ta metoda zwraca 404: "Not Found".
            Jest to po prostu skrót, by sobie oszczędzić pisania.
        """
        abort(404, message=f"User {user_id} doesn't exist!")

    @staticmethod
    def get_friends_list(user_id):
        """
            Ta metoda zwraca listę przyjaciół użytkownika
        """
        user = User.get_user_from_id(user_id)
        friends_list = user["friends_list"]
        return friends_list
        
    def get(self):
        """
            Ta metoda obsługuje zapytanie HTTP GET na endpoint użytkowników.
            Zwraca podstawowe informacje o użytkowniku.
        """
        args = self.user_parser.parse_args() # Użyj parsera do przeczytania argumentów
        user = User.get_user_from_id(args["_id"])
        return {"name": user["name"]}

    def post(self):
        """
            Ta metoda obsługuje zapytanie HTTP POST na endpoint użytkowników.
            Służy do obsługi znajomych.
        """
        args = self.user_parser.parse_args() # Użyj parsera do przeczytania argumentów

        if args["action"] == "add_friend": # Jeśli zapytanie to prośba o dadanie przyjaciela
            user = Auth.get_user_id(args["key"])
            friend = args["_id"]
            friends_list = User.get_friends_list(user)
            friends_list.append(friend) # Dodaj ID przyjaciela do listy przyjaciół
            mongo.db.users.update_one({"_id": user}, {"$set": {"friends_list": friends_list}}) # I zaktualizuj to w bazie

        if args["action"] == "remove_friend": # Jeśli zapytanie to prośba o usunięcie przyjaciela
            user = Auth.get_user_id(args["key"])
            friend = args["_id"]
            friends_list = User.get_friends_list(user)
            if friend not in friends_list: # I jeśli znajduje się on na liście przyjaciół
                abort(404, message=f"User {friend} is not a friend of user {user}") # (Jeśli tak nie jest, zwróć 404: "Not Found")
            friends_list.remove(friend) # Usuń go z listy przyjaciół
            mongo.db.users.update_one({"_id": user}, {"$set": {"friends_list": friends_list}}) # I zaktualizuj to w bazie
            

    def update(self):
        """
            Ta metoda obsługuje zapytanie HTTP UPDATE na endpoint użytkowników.
            Zapytanie UPDATE służy do modyfikowania informacji o użytkowniku
        """
        args = self.user_parser.parse_args() # Użyj parsera do przeczytania argumentów
        user = self.get_user_from_id(args["_id"])
        if Auth.get_user_id(args["key"]) != args["_id"]: # Jeśli właściciel klucza się nie zgadza
            abort(401, f"User {Auth.get_user_id(args['key'])} not authorized to update user {args['_id']}") # Zwróć 401: "Unauthorized"
        mongo.db.users.update_one({"_id": args["_id"]}, {"$set": {"name": args["name"], "brithday": args["birthday"], "gender": args["gender"], "friends_list": []}}) # Zaktualizuj dane użytkownika
        return 200


# Dodanie endpointów i przypisanie im klas

api.add_resource(Auth, "/auth")
api.add_resource(Post, "/post")
api.add_resource(User, "/user")

# Uruchomienie serwera deweloperskiego, jeśli moduł jest uruchomiony jako skrypt

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
