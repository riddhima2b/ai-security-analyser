import subprocess
import sqlite3

user_input = input("Enter command: ")

subprocess.run(user_input, shell=True)

conn = sqlite3.connect("app.db")
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
conn.execute(query)