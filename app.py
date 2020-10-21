import pyshark
import pymysql
import datetime
from database import *
from pathlib import Path

# TODO: Add src_host and dst_host from IP layer.
#       Choose pcap file and make path OS agnostic.
#       Parse xml in msg_body.

startTime = datetime.datetime.now()

def check_file_path(filename):
    full_path = Path.cwd().joinpath('traces', filename)
    if full_path.exists():
        return full_path
    else:
        return None

def connect_to_db():
    try:
        conn = pymysql.connect(host=db_host, port=int(db_port), db=db_name, user=db_user, password=db_password)
        print("\nConnection to DB established sucessfully.\n")
    except pymysql.MySQLError as e:
        print("Could not connect to DB --> ", e)
        sys.exit()
    return conn


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

#print(create_table_cmd)


cap = pyshark.FileCapture('.\\traces\\a.pcap')


# Choose only one packet for testing
#packet = cap_a[0]


# Connect to DB
conn = connect_to_db()
cursor = conn.cursor()

# Create table if it does not exist
cursor.execute(create_table_cmd)



#############################################################################
#   Return insert command for table (name of table) and columns (iterable)
#############################################################################

def insert_statement(table, columns):
    column_names = ', '.join(columns)
    placeholders = ', '.join(['%s'] * len(columns))
    return f'INSERT INTO {table} ({column_names}) VALUES ({placeholders});'

######################################################################################################
#
#   For each packet in the pcap file:
#
#   1. Create a dictionary that will hold the key,value pairs found in the packet,
#      IF there is a corresponding key entry in the required_fields.
#      First entry of this dictionary is the sniff_time.
#
#   2. Create a tuple that will hold only the values for each field contained in the required_fields.
#      Will be used for the DB insert command. First entry of this tuple is the sniff_time.
#
#   3. If there is a SIP layer in the packet, for each field name that is contained
#      in the required_fields, update the dictionary and the tuple.#
#
#######################################################################################################

print("Importing pcap to DB...")

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
        stat = insert_statement("sip_test_new", found_fields.keys())
        #print(stat, values_tuple)
        cursor.execute(stat, values_tuple)

conn.commit()

print("\nImporting completed!\n")

print("Execution time: {}".format(datetime.datetime.now() - startTime))

