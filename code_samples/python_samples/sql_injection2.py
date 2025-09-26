import pymysql

db = pymysql.connect("localhost","user","pass","testdb")
cursor = db.cursor()

search = input("Search product: ")

# Vulnerable concatenation
sql = "SELECT * FROM products WHERE name LIKE '%" + search + "%';"
cursor.execute(sql)

for row in cursor.fetchall():
    print(row)

db.close()
