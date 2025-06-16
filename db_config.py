import MySQLdb

def get_connection():
    return MySQLdb.connect(
        host="localhost",
        user="root",
        password="Ahmed.4091",
        database="shedeye"
    )
