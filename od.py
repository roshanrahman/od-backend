from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY'] = 'OnDutyRegistrationSSVR'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'od_register.db')

db = SQLAlchemy(app)

class Student(db.Model):
    id = db.Column(db.String(500), primary_key=True)
    name = db.Column(db.String(60))
    username = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(60))
    register_no = db.Column(db.String(10), unique=True)

class Faculty(db.Model):
    id = db.Column(db.String(500), primary_key=True)
    name = db.Column(db.String(60))
    username = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(60))

class Admin(db.Model):
    id = db.Column(db.String(500), primary_key=True)
    name = db.Column(db.String(60))
    username = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(60))   
    admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if(data['type']=='admin'):
                current_user = Admin.query.filter_by(id=data['id']).first()
            elif(data['type']=='student'):
                current_user = Student.query.filter_by(id=data['id']).first()
            else:
                current_user = Faculty.query.filter_by(id=data['id']).first()        

        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated    

@app.route('/student', methods=['POST'])
@token_required
def create_student(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')    

    new_student = Student(id=str(uuid.uuid4()), name=data['name'], username=data['username'], password=hashed_password, register_no=data['register_no'])
    db.session.add(new_student)
    db.session.commit()

    return jsonify({'message': 'New Student created!'})    

@app.route('/student', methods=['GET'])
@token_required
def get_all_student(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    students = Student.query.all()

    output = []

    for student in students:
        student_data = {}
        student_data['id'] = student.id
        student_data['name'] = student.name
        student_data['username'] = student.username
        student_data['password'] = student.password
        student_data['register_no'] = student.register_no
        output.append(student_data)

    return jsonify({'students': output})    

@app.route('/faculty', methods=['POST'])
@token_required
def create_faculty(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_faculty = Faculty(id=str(uuid.uuid4()), name=data['name'], username=data['username'], password=hashed_password)
    db.session.add(new_faculty)
    db.session.commit()

    return jsonify({'message': 'New Faculty created!'})

@app.route('/faculty', methods=['GET'])
@token_required
def get_all_faculty(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    faculties = Faculty.query.all()

    output = []

    for faculty in faculties:
        faculty_data = {}
        faculty_data['id'] = faculty.id
        faculty_data['name'] = faculty.name
        faculty_data['username'] = faculty.username
        faculty_data['password'] = faculty.password
        output.append(faculty_data)

    return jsonify({'students': output})   

@app.route('/admin', methods=['POST'])
def create_admin():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_admin = Admin(id=str(uuid.uuid4()), name=data['name'], username=data['username'], password=hashed_password, admin = True)
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'New Admin created!'})

@app.route('/admin', methods=['GET'])
@token_required
def get_all_admins(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    admins = Admin.query.all()

    output = []

    for admin in admins:
        admin_data = {}
        admin_data['id'] = admin.id
        admin_data['name'] = admin.name
        admin_data['username'] = admin.username
        admin_data['password'] = admin.password
        admin_data['admin'] = admin.admin

        output.append(admin_data)

        return jsonify({'admin': output})

@app.route('/admin/<username>', methods=['DELETE'])
def delete_admin(username):
    admin = Admin.query.filter_by(username=username).first()

    if not admin:
        return jsonify({'error': 'No User found!'})

    db.session.delete(admin)
    db.session.commit()

    return jsonify({'message': 'The admin has been deleted!'})        

@app.route('/student/<username>', methods=['DELETE'])
@token_required
def delete_student(current_user, username):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})

    student = Student.query.filter_by(username=username).first()

    if not student:
        return jsonify({'error': 'No Student found!'})

    db.session.delete(student)
    db.session.commit()

    return jsonify({'message': 'The Student has been deleted!'})

@app.route('/faculty/<username>', methods=['DELETE'])
@token_required
def delete_faculty(current_user, username):
    if not current_user.admin:
        return jsonify({'message': 'Only admin can perform this function'})
    faculty = Faculty.query.filter_by(username=username).first()

    if not faculty:
        return jsonify({'error': 'No Faculty found!'})

    db.session.delete(faculty)
    db.session.commit()

    return jsonify({'message': 'The Faculty has been deleted'})    


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    student = Student.query.filter_by(username=auth.username).first()
    faculty = Faculty.query.filter_by(username=auth.username).first()
    admin = Admin.query.filter_by(username=auth.username).first()    

    if(student):
        if check_password_hash(student.password, auth.password):
            token = jwt.encode({'id' : student.id, 'type' : 'student'}, app.config['SECRET_KEY'])

            return jsonify({'token': token.decode('UTF-8')})

        else:
            return make_response('could not verify password student', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    elif(faculty):
        if check_password_hash(faculty.password, auth.password):
            token = jwt.encode({'id' : faculty.id, 'type' : 'faculty'}, app.config['SECRET_KEY'])

            return jsonify({'token': token.decode('UTF-8')})

        else:
            return make_response('could not verify password faculty', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    elif(admin):
        if check_password_hash(admin.password, auth.password):
            token = jwt.encode({'id' : admin.id, 'type' : 'admin'}, app.config['SECRET_KEY'])
            
            return jsonify({'token': token.decode('UTF-8')})

        else:
            return make_response('could not verify password admin', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    else:        
        return make_response('could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})     


if __name__ == '__main__':
    app.run(debug=True) 