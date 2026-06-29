import sqlite3 as sql
import time
import random
import hashlib


def insertUser(username, password, DoB):
    if len(password) < 8:
        return False

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()
    return True


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    incoming_password_hash = hashlib.sha256(password.encode()).hexdigest()
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, incoming_password_hash),
    )

    if cur.fetchone() != None:
        # Plain text log of visitor count as requested by Unsecure PWA management
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        con.close()
        return True

    con.close()
    return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()


def save2FASecret(username, secret):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET twofa_secret = ? WHERE username = ?",
        (secret, username)
    )
    con.commit()
    con.close()


def get2FASecret(username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT twofa_secret FROM users WHERE username = ?",
        (username,)
    )
    result = cur.fetchone()
    con.close()
    if result:
        return result[0]
    return None
