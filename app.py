import pyshark
import pymysql
import datetime
from database import *
from pathlib import Path
from sqlalchemy import create_engine
from dotenv import load_dotenv
import sqlite3
import database

# TODO: Add src_host and dst_host from IP layer.
#       Choose pcap file from file browser and make path OS agnostic.
#       Check for module parse xml in msg_body.

startTime = datetime.datetime.now()

cap = pyshark.FileCapture('.\\traces\\calls.pcap')

# MySQL config
db_user = environ.get('DB_USERNAME')
db_password = environ.get('DB_PASSWORD')
db_host = environ.get('DB_HOST')
db_port = environ.get('DB_PORT')
db_name = environ.get('DB_NAME')

required_fields =  [
    'sniff_time',
    'request_line',
    'status_line',
    'msg_hdr',
    'msg_body'
]

# Construct SQL table creation command based on required fields.

create_table_cmd = "CREATE TABLE IF NOT EXISTS sip_test_new (id INT AUTO_INCREMENT PRIMARY KEY,"
for item in required_fields[:-1]:
    create_table_cmd += "\n" + item + " text,"
create_table_cmd += "\n" + required_fields[-1] + " text" + "\n);"

menu = """

Please select which DB to parse pcap file to:

1) SQLite
2) MySQL
3) Exit

NOTE: pcap files must be placed in "traces" directory.

Your selection: """

def construct_insert_statement(db, table, columns):
    column_names = ', '.join(columns)
    if db == 'sqlite':
        placeholders = ', '.join(['?'] * len(columns))
        return f'INSERT INTO {table} ({column_names}) VALUES ({placeholders})'
    elif db == 'mysql':
        placeholders = ', '.join(['%s'] * len(columns))
        return f'INSERT INTO {table} ({column_names}) VALUES ({placeholders});'


######################################################################################################
#
#   For each packet in the pcap file:
#
#   1. Create a dictionary that will hold the key,value pairs found in the packet,
#      only if there is a corresponding key entry in the required_fields.
#      First entry of this dictionary is the sniff_time.
#
#   2. Create a tuple that will hold only the values for each field contained in the required_fields.
#      This will be used for the DB insert command. First entry of this tuple is the sniff_time.
#
#   3. If there is a SIP layer in the packet, for each field name that is contained
#      in the required_fields, update the dictionary and the tuple.
#
#######################################################################################################


def insert_to_db(db, cap):
    for idx, packet in enumerate(cap):
        values_tuple = ()
        found_fields = {}
        sniff_time = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f")
        found_fields['sniff_time'] = sniff_time
        values_tuple += (sniff_time,)
        if "SIP" in str(packet.layers):
            for field_name in packet['SIP'].field_names:
                f_name = packet['SIP']._sanitize_field_name(field_name)
                f_value = packet['SIP'].get_field_value(field_name)
                if f_name in required_fields:
                    found_fields[f_name] = f_value
                    values_tuple += (f_value,)
            if db == 'sqlite':
                stat = construct_insert_statement('sqlite', "sip_test_new", found_fields.keys())
                conn.execute(stat, values_tuple)
            elif db == 'mysql':
                stat = construct_insert_statement('mysql', "sip_test_new", found_fields.keys())
                cursor.execute(stat, values_tuple)
    conn.commit()



user_input = input(menu)

while user_input != '3':
    if user_input == '1':
        conn = sqlite3.connect('database.db')
        conn.execute(create_table_cmd)
        insert_to_db('sqlite', cap)
        print("Successfully committed to SQLite DB.")
        break
    elif user_input == '2':
        conn = connect_to_mysql_db()
        cursor = conn.cursor()
        cursor.execute(create_table_cmd)
        insert_to_db('mysql', cap)
        print("Successfully committed to MySQL DB.")
        break
    elif user_input == '3':
        pass
    else:
        print("\nInvalid option, please try again.\n")
        user_input = input(menu)




