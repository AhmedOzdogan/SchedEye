import os
import MySQLdb
from dotenv import load_dotenv
load_dotenv()

def get_connection():
    return MySQLdb.connect(
        host=os.getenv("MYSQLHOST"),
        port=int(os.getenv("MYSQLPORT")), # type: ignore
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE")
    )