from os import environ, path
import sys
from dotenv import load_dotenv
import pymysql

# Expects .env file in the root directory
load_dotenv()

# MySQL database config
db_user = environ.get('DB_USERNAME')
db_password = environ.get('DB_PASSWORD')
db_host = environ.get('DB_HOST')
db_port = environ.get('DB_PORT')
db_name = environ.get('DB_NAME')

def connect_to_mysql_db():
    try:
        conn = pymysql.connect(host=db_host, port=int(db_port), db=db_name, user=db_user, password=db_password)
        print("\nConnection to DB established sucessfully")
    except pymysql.MySQLError as e:
        print(e)
        sys.exit()
    return conn
