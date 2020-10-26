from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

from flask_cors import CORS
from flaskext.mysql import MySQL

app = Flask(__name__)

CORS(app)

mysql = MySQL()

app.config['MYSQL_DATABASE_USER'] = 'dummy'
app.config['MYSQL_DATABASE_PASSWORD'] = 'Raman@sr7'
app.config['MYSQL_DATABASE_DB'] = 'craiglist'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['JWT_SECRET_KEY'] = 'secret'

mysql.init_app(app)
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

    conn = mysql.connect()
    cursor = conn.cursor()

    query = "select password from user where email='{}';".format(email)
    cursor.execute(query)

    hashed_password = cursor.fetchone()[0]
    
    print("Hashed password: {}".format(hashed_password))

    cursor.close()
    conn.close()

    if hashed_password == password:
        access_token = create_access_token(identity={'email':email})
    

        return jsonify({'status':"success", 'access_token':access_token, 'error':'None'}), 200


    else:
        return jsonify({'status':"failure", 'access_token':None, 'error':'Invalid Credentials'}), 200


@app.route('/unsafe/login', methods=['POST'])
def unsafe_login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    conn = mysql.connect()
    cursor = conn.cursor()

    query = "select * from user where email="+email+"and password="+password+";"
    print("Query is")
    print(query)
    cursor.execute(query)

    hashed_password = cursor.fetchone()
    
    print("Hashed password: {}".format(hashed_password))

    cursor.close()
    conn.close()

    if hashed_password:
        access_token = create_access_token(identity={'email':email})
    

        return jsonify({'status':"success", 'access_token':access_token, 'error':'None'}), 200


    else:
        return jsonify({'status':"failure", 'access_token':None, 'error':'Invalid Credentials'}), 200



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    id = data['id']
    email = data['email']
    password = data['password']

    conn = mysql.connect()
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

    conn = mysql.connect()
    cursor = conn.cursor()

    query = "select * from product where prod_name like '%{}%'".format(prod_name)
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
    prod_id = data['prod_id']
    prod_name = data['prod_name']
    prod_price = data['prod_price']

    conn = mysql.connect()
    cursor = conn.cursor()

    cursor.execute("insert into product (prod_id, prod_name, prod_price) values ({}, '{}', {})".format(prod_id, prod_name, prod_price))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'status':"success"})


@app.route('/cookie/monster')
def get_cookies():

    cookie = request.args.get("cookie")
    print(request.data)
    print(cookie)
    return jsonify(
        {
            "status": "sucess",
        }
    )

def transform_product_details(items):

    meta = ['prod_id', 'prod_name', 'prod_price']
    data = []

    for item in items:
        data.append(dict(zip(meta, list(item))))


    return meta, data




if __name__ == '__main__':

    app.run(debug=True, port=3000, host='127.0.0.1')
