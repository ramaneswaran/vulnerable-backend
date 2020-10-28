from flask import Flask
from flask import jsonify
from flask import request

from peewee import *

import sqlite3

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

from flask_cors import CORS

app = Flask(__name__)

CORS(app)

safe_db = SqliteDatabase('./safe.db')

# Usermodel

class BaseModel(Model):
    class Meta:
        database = safe_db 


class SafeUser(BaseModel):
    email = CharField(unique=True)
    password = CharField(unique=True) 

class SafeProduct(BaseModel):
    prod_name = CharField(unique=True)
    prod_description = TextField()


# Connection
safe_db.connect()
safe_db.create_tables([SafeUser, SafeProduct])


database = r"./dummy.db"


app.config['JWT_SECRET_KEY'] = 'secret'

jwt = JWTManager(app)


@app.route('/status')
def status():
    return jsonify(
        {
            'status': 'Up',
        }
    )

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    query = "select password from user where email='{}';".format(email)
    cursor.execute(query)

    hashed_password = cursor.fetchone()

    if hashed_password is not None:
        
        hashed_password = hashed_password[0]

        print("Hashed password: {}".format(hashed_password))

        cursor.close()
        conn.close()

        if hashed_password == password:
            print("works")
            access_token = create_access_token(identity={'email':email})
        

            return jsonify({'status':"success", 'access_token':access_token, 'error':'None'}), 200


        else:
            return jsonify({'status':"failure", 'access_token':None, 'error':'Invalid Credentials'}), 200

    else:
        return jsonify({'status':"failure", 'access_token':None, 'error':'Invalid Credentials'}), 200



@app.route('/orm/register', methods=['POST'])
def orm_register():
    
    data = request.get_json()
    email = data['email']
    password = data['password']


    user = SafeUser(email=email, password=password)
    user.save()
    
    return jsonify({
        'status': 'success'
    })


@app.route('/orm/login', methods=['POST'])
def orm_login():
    
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = SafeUser.get_or_none(email=email)

    if user is not None:
        if password == user.password:
            return jsonify({
                'status': 'success'
            })

    else:

        return jsonify({
            'status': 'failure'
        })


@app.route('/orm/products', methods=['POST'])
def orm_products():
    
    data = request.get_json()
    
    prod_name = data['prod_name']

    
    print(prod_name)

    query = SafeProduct.select().where(SafeProduct.prod_name.contains(prod_name))

    products = [tuple(item.values())[1:] for item in query.dicts()]

    meta, data = transform_product_details(products)
    

    if prod_name == "":
        data = []
        
    return jsonify({
        'status':'Success',
        'data': data,
        'meta':meta,
    })



@app.route('/unsafe/login', methods=['POST'])
def unsafe_login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    query = "select password from user where email='{}' and password='{}';".format(email, password)
    cursor.execute(query)

    item = cursor.fetchone()

    if  item is not None:

        access_token = create_access_token(identity={'email': item[0]})
        return jsonify({'status':"success", 'access_token':access_token, 'error':'None'}), 200


    else:
        return jsonify({'status':"failure", 'access_token':None, 'error':'Invalid Credentials'}), 200



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    id = data['id']
    email = data['email']
    password = data['password']

    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    query = "insert into user (id, email, password) values ({},'{}','{}')".format(id, email, password)
    print(query)
    cursor.execute(query)
    conn.commit()
    cursor.close()
    conn.close()

    
    access_token = create_access_token(identity={'email':email})
    

    return jsonify({'status':"success", 'access_token':access_token, 'error':'None'}), 200


@app.route('/products', methods=['POST'])
def product_details():
    
    data = request.get_json()
    
    prod_name = data['prod_name']

    
    print(prod_name)

    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    # query = "select * from product where prod_name like '%{}%'".format(prod_name)
    query = "select prod_name, prod_description from product where prod_name like '%"+prod_name+"%';"
    cursor.execute(query)
    products = cursor.fetchall()

    meta, data = transform_product_details(products)
    
    cursor.close()
    conn.close()

    if prod_name == "":
        data = []
        

    return jsonify({
        'status':'Success',
        'data': data,
        'meta':meta,
    })

@app.route('/add/product', methods=['POST'])
def add_product():
    data = request.get_json()

    prod_name = data['prod_name']
    prod_description = data['prod_description']

    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    cursor.execute("insert into product (prod_name, prod_description) values ('{}', '{}')".format(prod_name, prod_description))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'status':"success"})


@app.route('/cookie/monster', methods=['POST'])
def get_cookies():

    form_data = request.form

    cookies = parse_cookie_string(form_data['cookie'])

    print(cookies)
    
    return jsonify(
        {
            "status": "success",
        }
    )

@app.route('/phishing/monster', methods=['POST'])
def get_credentials():

    data = request.get_json()
    
    username = data['email']
    password = data['password']


    print(username)
    print(password)

    return jsonify(
        {
            "status": "success",
        }
    )



def parse_cookie_string(cookie_string):

    items = [item.split('=') for item in cookie_string.split(';')]
    cookies = {key:value for key,value in items}
    return cookies

def transform_product_details(items):

    meta = ['prod_name', 'prod_description']
    data = []

    for item in items:
        data.append(dict(zip(meta, list(item))))


    return meta, data




if __name__ == '__main__':

    app.run(debug=True, port=3000, host='127.0.0.1')
