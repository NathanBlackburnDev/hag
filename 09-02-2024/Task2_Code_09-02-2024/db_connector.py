import sqlite3

class Database:
    # Initalise database name
    def __init__(self):
        self.DBname = 'database.db'

    # Connection method
    def connect(self):
        conn = None
        try:
            conn = sqlite3.connect(self.DBname)
        except Exception as e:
            print(e)

        return conn

    # Disconnection method
    def disconnect(self, conn):
        conn.close()

    # Query method
    def queryDB(self, command, params=[]):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(command, params)
        result = cur.fetchall()
        self.disconnect(conn)
        return result

    # Update method
    def updateDB(self, command, params=[]):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(command, params)
        conn.commit()
        result = cur.fetchall()
        self.disconnect(conn)
        return result