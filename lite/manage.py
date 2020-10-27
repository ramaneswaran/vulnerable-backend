import sqlite3
import pandas as pd


database = r"./dummy.db"

conn = sqlite3.connect(database)

cursor = conn.cursor()

# Creating user table
print("[INFO] Creating user table ..")
query = "create table user (id int primary key not null, email text not null, password char(20) not null);"
cursor.execute(query)
conn.commit()
print("[INFO] Done")

# Insertion into user table
print("[INFO] Inserting into user table ..")
df = pd.read_csv('../data/User_table.csv')

for idx, row in df.iterrows():
    query = "insert into user (id, email, password) values ({},'{}','{}');".format(row['ID'], row['EMAIL'], row['PASSWORD'])
    cursor.execute(query)
    conn.commit()
print("[INFO] Done")


# Creating user info table
print("[INFO] Creating table user info")
query = "create table userinfo (id int not null, fullname text not null, age int not null, address char(50) not null, \
         phone char(10) primary key not null, foreign key (id) references user (id));"

cursor.execute(query)
conn.commit()
print("[INFO] Done")

print("[INFO] Inseting into user info table")
df = pd.read_csv('../data/USERINFO.csv')

for idx, row in df.iterrows():
    query = "insert into userinfo (id, fullname, age, address, phone) values ({},'{}', {}, '{}', '{}');".format(row['ID'], 
            row['FULLNAME'], row['AGE'], row['ADDRESS'], row['PHONE'])

    cursor.execute(query)
    conn.commit()
print("[INFO] Done")


# Creating product table
print("[INFO] Creating product table")
query = "create table product (prod_name char(50) not null, prod_description char(250) not null);"
cursor.execute(query)
conn.commit()
print("[INFO] Done")

# Insetion to product table
print("[INFO] Inseting into product table ..")
df = pd.read_csv('../data/PRODUCT.csv')

for idx, row in df.iterrows():
    query = "insert into product (prod_name, prod_description) values ('{}', '{}');".format(row['PROD_NAME'], row['PROD_DESC'])
    cursor.execute(query)
    conn.commit()
print("[INFO] Done")

conn.close()
