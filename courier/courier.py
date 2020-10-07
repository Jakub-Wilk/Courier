from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
from flask_pymongo import PyMongo
from hashlib import sha256
from base64 import urlsafe_b64encode
from datetime import datetime
import bcrypt

app = Flask(__name__)
app.config[
    "MONGO_URI"
] = "mongodb://courier-api:CourierApi@couriercluster-shard-00-00.uxoop.mongodb.net:27017,couriercluster-shard-00-01.uxoop.mongodb.net:27017,couriercluster-shard-00-02.uxoop.mongodb.net:27017/courier-data?ssl=true&replicaSet=atlas-bmdura-shard-0&authSource=admin&retryWrites=true&w=majority"
api = Api(app)
mongo = PyMongo(app)


class Auth(Resource):
    auth_parser = reqparse.RequestParser()
    auth_parser.add_argument("username")
    auth_parser.add_argument("password")
    auth_parser.add_argument("access_key")

    @staticmethod
    def update_date(access_key):
        if mongo.db.auth.find_one({"key": access_key}) is None:
            abort(401, message=f"Access key {access_key} is invalid!")
        mongo.db.auth.update_one({"key": access_key, "$set": {"date": datetime.now()}})
        return 200

    @staticmethod
    def check_access(access_key):
        query_result = mongo.db.auth.find_one({"key": access_key})
        if query_result is None:
            abort(401, message=f"Access key {access_key} is invalid!")
        delta = query_result["date"] - datetime.now()
        if delta.seconds // 60 >= 10:
            mongo.db.auth.delete_one({"key": access_key})
            abort(403, message=f"Access key {access_key} has expired!")
        return 200

    @staticmethod
    def check_update_access(access_key):
        if Auth.check_access(access_key):
            return Auth.update_date(access_key)

    def get(self):
        args = self.auth_parser.parse_args()
        username = args["username"]
        password = args["password"]
        if args["access_key"]:
            return Auth.check_update_access(args["access_key"])
        user = mongo.db.users.find_one({"username": username})
        if user is None:
            abort(404, message=f"User {username} doesn't exist!")
        hashed_password = user["password"]
        if bcrypt.checkpw(
            urlsafe_b64encode(sha256(password.encode("utf-8")).digest()),
            hashed_password,
        ):
            key = urlsafe_b64encode(
                sha256(str(datetime.timestamp(datetime.now())).encode("utf-8")).digest()
            ).decode("utf-8")

            mongo.db.auth.insert_one(
                {
                    "key": key,
                    "user": username,
                    "date": datetime.now(),
                }
            )
            return key

    def post(self):
        args = self.auth_parser.parse_args()
        username = args["username"]
        password = args["password"]
        if mongo.db.users.find_one({"username": username}) is not None:
            abort(409, message=f"A user with username {username} already exists!")
        mongo.db.users.insert_one(
            {
                "username": username,
                "password": bcrypt.hashpw(
                    urlsafe_b64encode(sha256(password.encode("utf-8")).digest()),
                    bcrypt.gensalt(),
                ),
            }
        )
        return 200


class Post(Resource):
    post_parser = reqparse.RequestParser()
    post_parser.add_argument("content")
    post_parser.add_argument("user_id")

    def post_from_id(self, post_id):
        query_result = mongo.db.posts.find_one({"_id": post_id})
        return query_result

    def post_doesnt_exist(self, post_id):
        abort(404, message=f"Post {post_id} doesn't exist!")

    def get(self, post_id):
        post = self.post_from_id(post_id)
        if post is None:
            self.post_doesnt_exist(post_id)
        return post

    def put(self, post_id):
        args = self.post_parser.parse_args()
        post = {"_id": post_id, "content": args["content"], "user_id": args["user_id"]}
        if self.post_from_id(post_id) is None:
            mongo.db.posts.insert_one(post)
            return post, 201
        else:
            mongo.db.posts.update_one(
                {"_id": post_id}, {"$set": {"content": args["content"]}}
            )
            return post

    def delete(self, post_id):
        if self.post_from_id(post_id) is None:
            self.post_doesnt_exist(post_id)
        mongo.db.posts.delete_one({"_id": post_id})
        return post_id


class PostCollection(Resource):
    posts_parser = reqparse.RequestParser()
    posts_parser.add_argument("_id")
    posts_parser.add_argument("content")
    posts_parser.add_argument("user_id")

    def get(self):
        args = self.posts_parser.parse_args()
        post = mongo.db.posts.find_one({"_id": args["_id"]})
        if post is None:
            abort(404, message=f"Post {args['_id']} doesn't exist!")
        return post

    def post(self):
        args = self.posts_parser.parse_args()
        if mongo.db.posts.find_one({"_id": args["_id"]}) is None:
            mongo.db.posts.insert_one(args)
        else:
            abort(409, message=f"Post {args['_id']} already exists!")


api.add_resource(Auth, "/auth")
api.add_resource(Post, "/post/<post_id>")
api.add_resource(PostCollection, "/post")

if __name__ == "__main__":
    app.run(debug=True)
