import sqlite3

conn = sqlite3.connect("users.db")
c = conn.cursor()

username = input("Enter username: ")
password = input("Enter password: ")

# Vulnerable query
query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
print("Executing query:", query)
c.execute(query)
rows = c.fetchall()

for row in rows:
    print(row)

conn.close()
