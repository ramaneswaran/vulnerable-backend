from peewee import *
import pandas as pd 

safe_db = SqliteDatabase('./safe.db')

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


# Insertion into user table
print("[INFO] Inserting into user table ..")
df = pd.read_csv('../data/User_table.csv')

for idx, row in df.iterrows():
    user = SafeUser(email=row['EMAIL'], password=row['PASSWORD'])
    user.save()
print("[INFO] Done")


# Insetion to product table
print("[INFO] Inseting into product table ..")
df = pd.read_csv('../data/PRODUCT.csv')

for idx, row in df.iterrows():
    product = SafeProduct(prod_name=row['PROD_NAME'], prod_description=row['PROD_DESC'])
    product.save()
print("[INFO] Done")