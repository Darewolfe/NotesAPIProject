from flask import Flask, request
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy  # Import necessary modules from Flask and Flask-RESTful to database
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
jwt = JWTManager(app)

@app.route('/')
def home():
    return {"message": "Notes API is running", "endpoints": ["/notes/<id>"]}

'''
lines 12 - 15: Validates the arguments for the PUT request to create a new note.
(Kind of like a error message for what is needed)
'''
note_post_args = reqparse.RequestParser()
note_post_args.add_argument("title", type=str, help="Title of the note is required", required=True) #Type of argument needed and error message for what is needed
note_post_args.add_argument("content", type=str, help="The content of the note is required", required=True)

note_put_args = reqparse.RequestParser()
note_put_args.add_argument("title", type=str, help="Title of the note is required", required=True)
note_put_args.add_argument("content", type=str, help="The content of the note is required", required=True)

note_update_args = reqparse.RequestParser()
note_update_args.add_argument("title", type=str help="Tile of note is required")
note_update_args.add_argument("content", type=str, help="Content of note is required")

#Defines how the object should be cerialized when returned in a response.
resource_fields = {
    "id": fields.Integer,
    "title": fields.String,
    "content":fields.String,
    "user": fields.String,
    "login": fields.String
}

class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

#Model to store note data in database
class NoteModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String (100), nullable=False)
    content = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    #Gives repersentation of the NoteModel object
    def __repr__(self):
        return f"Note(title = {self.title}, content = {self.content}, user_id = {self.user_id})"

with app.app_context():
    db.create_all()  # Create the database tables if they don't exist

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if UserModel.query.filter_by(username=username).first():
        return {"message": "Username already exists"}, 409
    
    hashed_pw = generate_password_hash(password)
    new_user = UserModel(username=username, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return {"message": "User registered successfully"}, 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = UserModel.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password)
        token = create_access_token(identity=user.id)
        return {"token": token}, 200

class Note(Resource):
    @jwt_required()  # Protect this resource with JWT authentication
    @marshal_with(resource_fields)
    #Get methood to get a note from user by ID
    def get(self, note_id):
        user_id = get_jwt_identity()  # Get the user ID from the JWT token
        result = NoteModel.query.filter_by(id=note_id,user_id=user_id).first()
        if not result:
            abort(404,message="Note not found")
        return result
    
    @jwt_required()
    @marshal_with(resource_fields)
    #Post method to create a new note
    def post(self, note_id):
        user_id = get_jwt_identity()
        args = note_post_args.parse_args()
        result = NoteModel.query.filter_by(title=args['title']).first()
        
        if result:
            abort(409, message="Note title is taken")
        if NoteModel.query.filter_by(id=note_id).first():
            abort(409, message="Note ID already exists")

        note = NoteModel(id=note_id, title=args['title'], content=args['content'], user="default_user", login="default_login")
        db.session.add(note)
        db.session.commit()
        return note, 201
    
    @jwt_required()
    @marshal_with(resource_fields)
    def put(self,note_id):
        args = note_put_args.parse_args()
        user_id = get_jwt_identity()
        result = NoteModel.query.filter_by(id=note_id, user_id=user_id).first()
        if not result:
            abort(404, message="Note not found")
            
        result.title = args['title']
        result.content = args['content']
        db.session.commit()
        return result, 200
    
    @marshal_with(resource_fields)
    def patch(self, note_id):
        args = note_update_args.parse_args()
        result = NoteModel.query.filter_by(id=note_id).first()
        if not result:
            abort(404, message="Note not found")
        
        if args['title']:
            result.title= args['title']
        if args['content']:
            result.content = args['content']
        db.session.commit()
        return result
    
    @jwt_required()
    def delete(self, note_id):
        user_id = get_jwt_identity()
        result = NoteModel.query.filter_by(id=note_id, user_id=user_id).first()
        if not result:
            abort(404, message="Note not found")
        db.session.delete(result)
        db.session.commit()
        return '', 204


api.add_resource(Note, "/notes/<int:note_id>")

if __name__ == "__main__":
    app.run(debug=True)