from flask import Flask
from flask_restful import reqparse, abort, Api, Resource
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config[
    "MONGO_URI"
] = "mongodb://courier-api:CourierApi@couriercluster-shard-00-00.uxoop.mongodb.net:27017,couriercluster-shard-00-01.uxoop.mongodb.net:27017,couriercluster-shard-00-02.uxoop.mongodb.net:27017/courier-data?ssl=true&replicaSet=atlas-bmdura-shard-0&authSource=admin&retryWrites=true&w=majority"
api = Api(app)
mongo = PyMongo(app)


class Auth(Resource):
    auth_parser = reqparse.RequestParser()
    auth_parser.add_argument("content")


class Post(Resource):
    post_parser = reqparse.RequestParser()
    post_parser.add_argument("content")
    post_parser.add_argument("user_id")

    def post_from_id(self, post_id):
        query_result = mongo.db.posts.find_one({"_id": post_id})
        return query_result

    def post_doesnt_exist(self, post_id):
        abort(404, message=f"Post {post_id} doesn't exist")

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
            print(args)
        else:
            abort(409, message=f"Post {args['_id']} already exists!")


api.add_resource(Post, "/post/<post_id>", endpoint="post")
api.add_resource(PostCollection, "/post")

if __name__ == "__main__":
    app.run(debug=True)
