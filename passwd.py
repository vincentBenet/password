import base64
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.kdf.pbkdf2
import getpass
import sqlite3
import numpy
import hashlib
import random
import time


def create_tables():
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "categorie" (
            "id"	INTEGER NOT NULL UNIQUE,
            "name"	TEXT NOT NULL UNIQUE,
            PRIMARY KEY("id" AUTOINCREMENT)
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "location" (
            "id"	INTEGER NOT NULL UNIQUE,
            "name"	TEXT NOT NULL UNIQUE,
            PRIMARY KEY("id" AUTOINCREMENT)
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "mail" (
            "id"	INTEGER NOT NULL UNIQUE,
            "name"	TEXT NOT NULL UNIQUE,
            PRIMARY KEY("id" AUTOINCREMENT)
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "username" (
            "id"	INTEGER NOT NULL UNIQUE,
            "name"	TEXT NOT NULL UNIQUE,
            PRIMARY KEY("id" AUTOINCREMENT)
        );
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "passwd" (
            "id"	INTEGER NOT NULL UNIQUE,
            "description"	TEXT,
            "password"	TEXT,
            "id_categorie"	INTEGER,
            "id_location"	INTEGER,
            "id_username"	INTEGER,
            "id_mail"	INTEGER,
            PRIMARY KEY("id" AUTOINCREMENT)
        );
    ''')
    con.commit()
    
    
def get_key(key: str) -> bytes:
    kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=("0"*16).encode(),
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(key.encode()))


def encrypt(message: str, key: str) -> str:
    return Fernet(get_key(key)).encrypt(message.encode()).decode()
    

def decrypt(token: str, key: str) -> str:
    return Fernet(get_key(key)).decrypt(token.encode()).decode()

def clear():
    if sys.platform == "win32":
        os.system('cls')
    elif sys.platform == "linux":
        os.system('clear')
    else:
        print("\n"*50)


def main(action=None):
    print(f"-Choose action-")
    function = ask_dict({
        "Exit": lambda: exit(),
        "Show login": show_login,
        "New login": new_login,
        "Modify login": modify_login,
        "Delete login": delete_login,
        "New database": ask_master_key,
        "Change Master Key": change_master_key,
        "Import CSV": import_csv,
        "Export CSV": export_csv,
    })
    clear()
    function()


def import_csv():
    raise NotImplementedError
    
    
def export_csv():
    raise NotImplementedError


def new_login():
    description = input("Description: ")
    id_categorie = get_id("categorie")
    id_location = get_id("location")
    id_username = get_id("username")
    id_mail = get_id("mail")
    password = input("Password: ")
    return add_passwd(
        id_username, 
        id_mail, 
        id_categorie, 
        id_location, 
        description, 
        encrypt(password, master_key)
    )

def select_many(querry):
    cur.execute(querry)
    return numpy.array(cur.fetchall())


def get_ids_names(classe):
    res = select_many(f"SELECT id, name FROM {classe};").T
    if not len(res):
        return [], []
    return res


def get_id(classe):
    print(f"{classe = }")
    ids, names = get_ids_names(classe)
    name = ask_list(names)
    if name not in names:
        cur.execute(f'''
            INSERT INTO {classe} 
            (name) VALUES
            ('{name}');
        ''')
        con.commit()
        ids, names = get_ids_names(classe)
    
    return int(ids[names == name][0])


def add_passwd(username_id, mail_id, categorie_id, location_id, description, password):
    try:
        cur.execute(f'''
            INSERT INTO passwd 
            (description, password, id_categorie, id_location, id_username, id_mail) VALUES
            ('{description}', '{password}', '{categorie_id}', '{location_id}', '{username_id}', '{mail_id}');
        ''')
        con.commit()
        return True
    except Exception as e:
        print(e)
        return False

def modify_login():
    
    raise NotImplementedError
    
    
def delete_login():
    
    raise NotImplementedError
    

def get_password(id_password):
    cur.execute(f"SELECT id_categorie, id_location, id_username, id_mail, password, description FROM passwd WHERE id = {id_password};")
    id_categorie, id_location, id_username, id_mail, token, description = cur.fetchone()
    
    cur.execute(f"SELECT name FROM categorie WHERE id = {id_categorie};")
    categorie = cur.fetchone()[0]
    
    cur.execute(f"SELECT name FROM location WHERE id = {id_location};")
    location = cur.fetchone()[0]
    
    cur.execute(f"SELECT name FROM username WHERE id = {id_username};")
    username = cur.fetchone()[0]
    
    cur.execute(f"SELECT name FROM mail WHERE id = {id_mail};")
    mail = cur.fetchone()[0]
    
    return categorie, location, username, mail, decrypt(token, master_key), description


def show_password(categorie, location, username, mail, password, description):
    clear()
    print(f"Description: {description}")
    print(f"Categorie: {categorie}")
    print(f"Location: {location}")
    print(f"Username: {username}")
    print(f"Mail: {mail}")
    input("-" * 10 + " " + password + " " + "-" * 10)


def show_login():
    ids, descriptions, location_ids, categorie_ids = select_many(f"SELECT id, description, id_location, id_categorie FROM passwd;").T
    dico = {}
    for i, description in enumerate(descriptions):
        dico |= {f"{get_ids_names('categorie')[1][int(categorie_ids[i])-1]} | {description} | {get_ids_names('location')[1][int(location_ids[i])-1]}": int(ids[i])}
    categorie, location, username, mail, password, description = get_password(ask_dict(dico))
    show_password(categorie, location, username, mail, password, description)


def change_master_key(): 
    raise NotImplementedError
    
    
def ask_int(message):
    i = 0
    while True:
        user_input = input(f"{message}: ")
        try:
            action_id = int(user_input)
        except:
            if not i:
                print(f"'{user_input}' is not valid input, please try again")
                i += 1
            continue
        break
    return action_id


def ask_list(listo):
    i = 0
    while True:
        if not i:
            for i, key in enumerate(listo):
                print(f"{i} : {key}")
        user_input = input("Choose element [int] or enter new [str]:\n")
        if user_input == "":
            return "-"
        try:
            id_input = int(user_input)
        except:
            return user_input
        if id_input >= len(listo):
            if not i:
                print(f"{id_input} is not valid, please try again")
                i += 1
            continue
        for i, el in enumerate(listo):
            if i != id_input:
                continue
            break
        break
    return listo[i]



def ask_dict(dico):
    i = 0
    while True:
        if not i:
            for i, key in enumerate(dico):
                print(f"{i} : {key}")
        id_input = ask_int("Choose element")
        if id_input >= len(dico):
            if not i:
                print(f"{id_input} is not valid, please try again")
                i += 1
            continue
        for i, el in enumerate(dico):
            if i != id_input:
                continue
            break
        break
    print(f"-{el}-")
    return dico[el]


def check_master_key(_master_key, n=6):
    global master_key
    master_key = _master_key
    verif = hashlib.md5(master_key.encode()).hexdigest().encode()
    for i in range(10**n):
        verif = hashlib.md5(verif).hexdigest().encode()
    return verif


def urandom_from_random(rng, length):
    return bytes([rng.randint(0, 255) for i in range(length)])
    

def ask_master_key():
    global db_filename
    verif_md5 = check_master_key(getpass.getpass("Master key: "))
    db_filename = os.path.join(os.path.dirname(__file__), f"{verif_md5.decode()}.db")
    if not os.path.isfile(db_filename):
        print(f"-No Databases found using master key {master_key}-")
        return ask_dict({
            "Continue with new database": lambda: connect_db(),
            "Enter master key again": lambda: ask_master_key(),
            "Exit programm": lambda: exit(),
        })()
    connect_db()
    return True
    

def connect_db():
    global con, cur
    print(f"Connection to DB {db_filename}")
    con = sqlite3.connect(db_filename)
    cur = con.cursor()
    create_tables()


if __name__ == "__main__":
    ask_master_key()
    while True:
        clear()
        main()