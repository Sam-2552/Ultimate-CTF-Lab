from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, render_template_string
import sqlite3
import os
import hashlib
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room
import re
import bleach
import subprocess
from flask_cors import CORS


# logging.basicConfig(filename='/home/oilnwine/flaskapp.log', level=logging.DEBUG)
# #Then use logging commands throughout your Flask app to log relevant information
# logging.debug('Debug message')
# logging.info('Informational message')
# logging.error('Error message')

app = Flask(__name__)
# app.secret_key = "secret_key"
secret_key="helllo_kjghkjh"
app.config['SECRET_KEY'] = secret_key
print(secret_key)

# Enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SocketIO with CORS support
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading',
                   logger=True,
                   engineio_logger=True)

DATABASE = 'oilnwine.db'

def sanitize_html(html_content,allowed_tags=['b', 'i', 'u', 'a', 'iframe', 'br', 'video', 'embed', 'marquee'],allowed_attrs={
    'a': ['href', 'title'],   # Allow href and title attributes for <a> tags
    'iframe': ['src', 'width', 'height', 'frameborder', 'allow', 'allowfullscreen'],  # Attributes for iframes
    'video': ['src', 'width', 'height', 'controls', 'autoplay', 'loop'],
      'embed': ['src', 'type', 'width', 'height'],
      'marquee': ['behavior', 'direction', 'scrollamount', 'scrolldelay', 'loop']
}):
    return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attrs, strip=True)


def create_tables():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()

    # Create table log_details
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_details (
            id INTEGER PRIMARY KEY,
            user TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create table details
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS details (
            id INTEGER PRIMARY KEY,
            user TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data TEXT
        )
    ''')

    # Create table controls
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS controls (
            id INTEGER PRIMARY KEY,
            user TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data TEXT
        )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS add_logs (
        id INTEGER PRIMARY KEY,
        user TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        link TEXT
    )
    ''')

    # Create edit_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS edit_logs (
        id INTEGER PRIMARY KEY,
        edit_id INTEGER,
        title TEXT,
        alternate_title TEXT,
        lyrics TEXT,
        transliteration TEXT,
        chord TEXT,
        search_title TEXT,
        search_lyrics TEXT,
        youtube_link TEXT,
        create_date TEXT,
        modified_date TEXT,
        username TEXT
    )
    ''')

    # Create delete_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS delete_logs (
        id INTEGER PRIMARY KEY,
        delete_id INTEGER,
        title TEXT,
        alternate_title TEXT,
        lyrics TEXT,
        transliteration TEXT,
        chord TEXT,
        search_title TEXT,
        search_lyrics TEXT,
        youtube_link TEXT,
        create_date TEXT,
        modified_date TEXT,
        username TEXT
    )
    ''')

    conn.commit()
    conn.close()


def insert_logs(user):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO log_details (user, time) VALUES (?, datetime('now'))", (user,))
    conn.commit()
    conn.close()


def insert_details(user, data):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO details (user, time, data) VALUES (?, datetime('now'), ?)", (user, data))
    conn.commit()
    conn.close()


def insert_control(user, data):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO controls (user, time, data) VALUES (?, datetime('now'), ?)", (user, data))
    conn.commit()
    conn.close()


def create_connection():
    conn = sqlite3.connect(DATABASE)
    return conn


def remove_special_characters(input_string):
    # Define a regex pattern to match special characters
    # Matches any character that is not a letter, digit, or whitespace
    pattern = r'[^a-zA-Z0-9\s]'

    # Replace special characters with an empty string
    processed_string = re.sub(pattern, '', input_string)
    return processed_string


def create_users_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            otp INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            permission INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def create_songs_table():
    conn = create_connection()
    cursor = conn.cursor()

    # Create the songs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS songs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            alternate_title TEXT,
            lyrics TEXT,
            transliteration TEXT,
            chord TEXT,
            search_title TEXT,
            search_lyrics TEXT,
            youtube_link TEXT,
            create_date TEXT,
            modified_date TEXT,
            username TEXT,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()


def song_view(lyrics, transliteration_lyrics, chord):
    if transliteration_lyrics == "" or transliteration_lyrics == None or transliteration_lyrics == "None":
        paragraphs = re.split(r'\r?\n|\r', lyrics)
        para_count = 1
        if chord == None or chord == "None":
            chord = ''
        else:
            chord = "<span id='chord' style='font-weight:bold;'>" + \
                chord + "</span><br>"
        formatted_song = f"<p id={para_count} style='border: 1px solid black;padding: 10px;'>{chord}"
        for paragraph in paragraphs:
            if paragraph == "":
                para_count += 1
                formatted_song += f"</p><p id={para_count} style='border: 1px solid black;padding: 10px;'>"
            else:
                formatted_song += f'{paragraph}<br>'
    else:
        if chord == None or chord == "None":
            chord = ''
        else:
            chord = "<span id='chord' style='font-weight:bold;'>" + \
                chord + "</span><br>"
        paragraphs1 = re.split(r'\r?\n|\r', lyrics)
        paragraphs2 = re.split(r'\r?\n|\r', transliteration_lyrics)
        print(paragraphs1)
        print(paragraphs2)
        allow1 = 0
        allow2 = 0
        para_count = 1
        formatted_song = f"<p id={para_count} style='border: 1px solid black;padding: 10px;'>{chord}"
        for i in range(max(len(paragraphs2), len(paragraphs1))):
            if allow1 == 0:
                try:
                    paragraphs1[i]
                except:
                    allow1 = 1
            if allow2 == 0:
                try:
                    paragraphs2[i]
                except:
                    allow2 = 1

            if allow1 == 0 and allow2 == 0:
                if paragraphs1[i] == "" or paragraphs2[i] == "":
                    para_count += 1
                    formatted_song += f"</p><p id={para_count} style='border: 1px solid black;padding: 10px;'>"
                else:
                    formatted_song += f"{paragraphs1[i]}<br><span style='color:green;'>{paragraphs2[i]}</span><br>"

            if allow1 == 1:
                if paragraphs2[i] == "":
                    para_count += 1
                    formatted_song += f"</p><p id={para_count} style='border: 1px solid black;padding: 10px; color:green;'>"
                else:
                    formatted_song += f'{paragraphs2[i]}<br>'

            if allow2 == 1:
                if paragraphs1[i] == "":
                    para_count += 1
                    formatted_song += f"</p><p id={para_count} style='border: 1px solid black;padding: 10px;'>"
                else:
                    formatted_song += f'{paragraphs1[i]}<br>'

    return formatted_song


# Call the function to create the 'songs' table
create_songs_table()

create_users_table()

create_tables()


@app.route('/download')
def download_db():
    # Introduce a vulnerability by accepting a filename parameter from the user
    db_file_path = request.args.get('filename', 'logs.db')  # Default to 'logs.db'

    return send_file(db_file_path, as_attachment=True)



@app.route('/')
def home():
    conn=create_connection()
    if 'username' in session:
        login = True
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

    else:
        login = False
        user = ""
        permission = 0

    cursor = conn.cursor()

    # Execute a query to select data from the 'songs' table
    cursor.execute('SELECT id, title, search_title, search_lyrics FROM songs')
    # Fetch all rows with the specified columns
    rows = cursor.fetchall()

    sorted_rows = sorted(rows, key=lambda x: x[1].lower())

    # print(rows)
    conn.close()

    return render_template("home.html", login=login, user=user, rows=sorted_rows, permission=permission)


@app.route('/tamil')
def tamil():
    conn=create_connection()
    if 'username' in session:
        login = True
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

    else:
        login = False
        user = ""
        permission = 0

    cursor = conn.cursor()

    # Execute a SELECT query to fetch all rows
    cursor.execute('SELECT id, title, search_title, search_lyrics FROM songs')

    # Fetch the results
    all_rows = cursor.fetchall()

    # Filter the results based on the search term using Python
    filtered_results = [row for row in all_rows if 'tamil' in row[1]
                        or 'Tamil' in row[1] or 'tamil' in row[2] or 'Tamil' in row[2]]

    # Process the filtered results

    # print(filtered_results)

    sorted_rows = sorted(filtered_results, key=lambda x: x[1].lower())

    # print(sorted_rows)

    # print(rows)
    conn.close()

    return render_template("tamil.html", login=login, user=user, rows=sorted_rows, permission=permission)


@app.route('/malayalam')
def malayalam():
    conn=create_connection()
    if 'username' in session:
        login = True
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

    else:
        login = False
        user = ""
        permission = 0

    cursor = conn.cursor()

    # Execute a SELECT query to fetch all rows
    cursor.execute('SELECT id, title, search_title, search_lyrics FROM songs')

    # Fetch the results
    all_rows = cursor.fetchall()

    # Filter the results based on the search term using Python
    filtered_results = [row for row in all_rows if 'malayalam' in row[1]
                        or 'Malayalam' in row[1] or 'malayalam' in row[2] or 'Malayalam' in row[2]]

    # Process the filtered results

    # print(filtered_results)

    sorted_rows = sorted(filtered_results, key=lambda x: x[1].lower())

    # print(sorted_rows)

    # print(rows)
    conn.close()

    return render_template("malayalam.html", login=login, user=user, rows=sorted_rows, permission=permission)


@app.route('/hindi')
def hindi():
    conn=create_connection()
    if 'username' in session:
        login = True
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

    else:
        login = False
        user = ""
        permission = 0

    cursor = conn.cursor()

    # Execute a SELECT query to fetch all rows
    cursor.execute('SELECT id, title, search_title, search_lyrics FROM songs')

    # Fetch the results
    all_rows = cursor.fetchall()

    # Filter the results based on the search term using Python
    filtered_results = [row for row in all_rows if 'hindi' in row[1]
                        or 'Hindi' in row[1] or 'hindi' in row[2] or 'Hindi' in row[2]]

    # Process the filtered results

    # print(filtered_results)

    sorted_rows = sorted(filtered_results, key=lambda x: x[1].lower())

    # print(sorted_rows)

    # print(rows)
    conn.close()

    return render_template("hindi.html", login=login, user=user, rows=sorted_rows, permission=permission)


@app.route('/telugu')
def telugu():
    conn=create_connection()
    if 'username' in session:
        login = True
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

    else:
        login = False
        user = ""
        permission = 0

    cursor = conn.cursor()

    # Execute a SELECT query to fetch all rows
    cursor.execute('SELECT id, title, search_title, search_lyrics FROM songs')

    # Fetch the results
    all_rows = cursor.fetchall()

    # Filter the results based on the search term using Python
    filtered_results = [row for row in all_rows if 'telugu' in row[1] or 'Telugu' in row[1] or 'Telegu' in row[1]
                        or 'telegu' in row[1] or 'telugu' in row[2] or 'Telugu' in row[2] or 'Telegu' in row[2] or 'telegu' in row[2]]

    # Process the filtered results

    # print(filtered_results)

    sorted_rows = sorted(filtered_results, key=lambda x: x[1].lower())

    # print(sorted_rows)

    # print(rows)
    conn.close()

    return render_template("telugu.html", login=login, user=user, rows=sorted_rows, permission=permission)


result_list = [[1, 1, 1, 'Genesis 1', 'Gen 1'], [2, 1, 2, 'Genesis 2', 'Gen 2'], [3, 1, 3, 'Genesis 3', 'Gen 3'], [4, 1, 4, 'Genesis 4', 'Gen 4'], [5, 1, 5, 'Genesis 5', 'Gen 5'], [6, 1, 6, 'Genesis 6', 'Gen 6'], [7, 1, 7, 'Genesis 7', 'Gen 7'], [8, 1, 8, 'Genesis 8', 'Gen 8'], [9, 1, 9, 'Genesis 9', 'Gen 9'], [10, 1, 10, 'Genesis 10', 'Gen 10'], [11, 1, 11, 'Genesis 11', 'Gen 11'], [12, 1, 12, 'Genesis 12', 'Gen 12'], [13, 1, 13, 'Genesis 13', 'Gen 13'], [14, 1, 14, 'Genesis 14', 'Gen 14'], [15, 1, 15, 'Genesis 15', 'Gen 15'], [16, 1, 16, 'Genesis 16', 'Gen 16'], [17, 1, 17, 'Genesis 17', 'Gen 17'], [18, 1, 18, 'Genesis 18', 'Gen 18'], [19, 1, 19, 'Genesis 19', 'Gen 19'], [20, 1, 20, 'Genesis 20', 'Gen 20'], [21, 1, 21, 'Genesis 21', 'Gen 21'], [22, 1, 22, 'Genesis 22', 'Gen 22'], [23, 1, 23, 'Genesis 23', 'Gen 23'], [24, 1, 24, 'Genesis 24', 'Gen 24'], [25, 1, 25, 'Genesis 25', 'Gen 25'], [26, 1, 26, 'Genesis 26', 'Gen 26'], [27, 1, 27, 'Genesis 27', 'Gen 27'], [28, 1, 28, 'Genesis 28', 'Gen 28'], [29, 1, 29, 'Genesis 29', 'Gen 29'], [30, 1, 30, 'Genesis 30', 'Gen 30'], [31, 1, 31, 'Genesis 31', 'Gen 31'], [32, 1, 32, 'Genesis 32', 'Gen 32'], [33, 1, 33, 'Genesis 33', 'Gen 33'], [34, 1, 34, 'Genesis 34', 'Gen 34'], [35, 1, 35, 'Genesis 35', 'Gen 35'], [36, 1, 36, 'Genesis 36', 'Gen 36'], [37, 1, 37, 'Genesis 37', 'Gen 37'], [38, 1, 38, 'Genesis 38', 'Gen 38'], [39, 1, 39, 'Genesis 39', 'Gen 39'], [40, 1, 40, 'Genesis 40', 'Gen 40'], [41, 1, 41, 'Genesis 41', 'Gen 41'], [42, 1, 42, 'Genesis 42', 'Gen 42'], [43, 1, 43, 'Genesis 43', 'Gen 43'], [44, 1, 44, 'Genesis 44', 'Gen 44'], [45, 1, 45, 'Genesis 45', 'Gen 45'], [46, 1, 46, 'Genesis 46', 'Gen 46'], [47, 1, 47, 'Genesis 47', 'Gen 47'], [48, 1, 48, 'Genesis 48', 'Gen 48'], [49, 1, 49, 'Genesis 49', 'Gen 49'], [50, 1, 50, 'Genesis 50', 'Gen 50'], [51, 2, 1, 'Exodus 1', 'Exo 1'], [52, 2, 2, 'Exodus 2', 'Exo 2'], [53, 2, 3, 'Exodus 3', 'Exo 3'], [54, 2, 4, 'Exodus 4', 'Exo 4'], [55, 2, 5, 'Exodus 5', 'Exo 5'], [56, 2, 6, 'Exodus 6', 'Exo 6'], [57, 2, 7, 'Exodus 7', 'Exo 7'], [58, 2, 8, 'Exodus 8', 'Exo 8'], [59, 2, 9, 'Exodus 9', 'Exo 9'], [60, 2, 10, 'Exodus 10', 'Exo 10'], [61, 2, 11, 'Exodus 11', 'Exo 11'], [62, 2, 12, 'Exodus 12', 'Exo 12'], [63, 2, 13, 'Exodus 13', 'Exo 13'], [64, 2, 14, 'Exodus 14', 'Exo 14'], [65, 2, 15, 'Exodus 15', 'Exo 15'], [66, 2, 16, 'Exodus 16', 'Exo 16'], [67, 2, 17, 'Exodus 17', 'Exo 17'], [68, 2, 18, 'Exodus 18', 'Exo 18'], [69, 2, 19, 'Exodus 19', 'Exo 19'], [70, 2, 20, 'Exodus 20', 'Exo 20'], [71, 2, 21, 'Exodus 21', 'Exo 21'], [72, 2, 22, 'Exodus 22', 'Exo 22'], [73, 2, 23, 'Exodus 23', 'Exo 23'], [74, 2, 24, 'Exodus 24', 'Exo 24'], [75, 2, 25, 'Exodus 25', 'Exo 25'], [76, 2, 26, 'Exodus 26', 'Exo 26'], [77, 2, 27, 'Exodus 27', 'Exo 27'], [78, 2, 28, 'Exodus 28', 'Exo 28'], [79, 2, 29, 'Exodus 29', 'Exo 29'], [80, 2, 30, 'Exodus 30', 'Exo 30'], [81, 2, 31, 'Exodus 31', 'Exo 31'], [82, 2, 32, 'Exodus 32', 'Exo 32'], [83, 2, 33, 'Exodus 33', 'Exo 33'], [84, 2, 34, 'Exodus 34', 'Exo 34'], [85, 2, 35, 'Exodus 35', 'Exo 35'], [86, 2, 36, 'Exodus 36', 'Exo 36'], [87, 2, 37, 'Exodus 37', 'Exo 37'], [88, 2, 38, 'Exodus 38', 'Exo 38'], [89, 2, 39, 'Exodus 39', 'Exo 39'], [90, 2, 40, 'Exodus 40', 'Exo 40'], [91, 3, 1, 'Leviticus 1', 'Lev 1'], [92, 3, 2, 'Leviticus 2', 'Lev 2'], [93, 3, 3, 'Leviticus 3', 'Lev 3'], [94, 3, 4, 'Leviticus 4', 'Lev 4'], [95, 3, 5, 'Leviticus 5', 'Lev 5'], [96, 3, 6, 'Leviticus 6', 'Lev 6'], [97, 3, 7, 'Leviticus 7', 'Lev 7'], [98, 3, 8, 'Leviticus 8', 'Lev 8'], [99, 3, 9, 'Leviticus 9', 'Lev 9'], [100, 3, 10, 'Leviticus 10', 'Lev 10'], [101, 3, 11, 'Leviticus 11', 'Lev 11'], [102, 3, 12, 'Leviticus 12', 'Lev 12'], [103, 3, 13, 'Leviticus 13', 'Lev 13'], [104, 3, 14, 'Leviticus 14', 'Lev 14'], [105, 3, 15, 'Leviticus 15', 'Lev 15'], [106, 3, 16, 'Leviticus 16', 'Lev 16'], [107, 3, 17, 'Leviticus 17', 'Lev 17'], [108, 3, 18, 'Leviticus 18', 'Lev 18'], [109, 3, 19, 'Leviticus 19', 'Lev 19'], [110, 3, 20, 'Leviticus 20', 'Lev 20'], [111, 3, 21, 'Leviticus 21', 'Lev 21'], [112, 3, 22, 'Leviticus 22', 'Lev 22'], [113, 3, 23, 'Leviticus 23', 'Lev 23'], [114, 3, 24, 'Leviticus 24', 'Lev 24'], [115, 3, 25, 'Leviticus 25', 'Lev 25'], [116, 3, 26, 'Leviticus 26', 'Lev 26'], [117, 3, 27, 'Leviticus 27', 'Lev 27'], [118, 4, 1, 'Numbers 1', 'Num 1'], [119, 4, 2, 'Numbers 2', 'Num 2'], [120, 4, 3, 'Numbers 3', 'Num 3'], [121, 4, 4, 'Numbers 4', 'Num 4'], [122, 4, 5, 'Numbers 5', 'Num 5'], [123, 4, 6, 'Numbers 6', 'Num 6'], [124, 4, 7, 'Numbers 7', 'Num 7'], [125, 4, 8, 'Numbers 8', 'Num 8'], [126, 4, 9, 'Numbers 9', 'Num 9'], [127, 4, 10, 'Numbers 10', 'Num 10'], [128, 4, 11, 'Numbers 11', 'Num 11'], [129, 4, 12, 'Numbers 12', 'Num 12'], [130, 4, 13, 'Numbers 13', 'Num 13'], [131, 4, 14, 'Numbers 14', 'Num 14'], [132, 4, 15, 'Numbers 15', 'Num 15'], [133, 4, 16, 'Numbers 16', 'Num 16'], [134, 4, 17, 'Numbers 17', 'Num 17'], [135, 4, 18, 'Numbers 18', 'Num 18'], [136, 4, 19, 'Numbers 19', 'Num 19'], [137, 4, 20, 'Numbers 20', 'Num 20'], [138, 4, 21, 'Numbers 21', 'Num 21'], [139, 4, 22, 'Numbers 22', 'Num 22'], [140, 4, 23, 'Numbers 23', 'Num 23'], [141, 4, 24, 'Numbers 24', 'Num 24'], [142, 4, 25, 'Numbers 25', 'Num 25'], [143, 4, 26, 'Numbers 26', 'Num 26'], [144, 4, 27, 'Numbers 27', 'Num 27'], [145, 4, 28, 'Numbers 28', 'Num 28'], [146, 4, 29, 'Numbers 29', 'Num 29'], [147, 4, 30, 'Numbers 30', 'Num 30'], [148, 4, 31, 'Numbers 31', 'Num 31'], [149, 4, 32, 'Numbers 32', 'Num 32'], [150, 4, 33, 'Numbers 33', 'Num 33'], [151, 4, 34, 'Numbers 34', 'Num 34'], [152, 4, 35, 'Numbers 35', 'Num 35'], [153, 4, 36, 'Numbers 36', 'Num 36'], [154, 5, 1, 'Deuteronomy 1', 'Deu 1'], [155, 5, 2, 'Deuteronomy 2', 'Deu 2'], [156, 5, 3, 'Deuteronomy 3', 'Deu 3'], [157, 5, 4, 'Deuteronomy 4', 'Deu 4'], [158, 5, 5, 'Deuteronomy 5', 'Deu 5'], [159, 5, 6, 'Deuteronomy 6', 'Deu 6'], [160, 5, 7, 'Deuteronomy 7', 'Deu 7'], [161, 5, 8, 'Deuteronomy 8', 'Deu 8'], [162, 5, 9, 'Deuteronomy 9', 'Deu 9'], [163, 5, 10, 'Deuteronomy 10', 'Deu 10'], [164, 5, 11, 'Deuteronomy 11', 'Deu 11'], [165, 5, 12, 'Deuteronomy 12', 'Deu 12'], [166, 5, 13, 'Deuteronomy 13', 'Deu 13'], [167, 5, 14, 'Deuteronomy 14', 'Deu 14'], [168, 5, 15, 'Deuteronomy 15', 'Deu 15'], [169, 5, 16, 'Deuteronomy 16', 'Deu 16'], [170, 5, 17, 'Deuteronomy 17', 'Deu 17'], [171, 5, 18, 'Deuteronomy 18', 'Deu 18'], [172, 5, 19, 'Deuteronomy 19', 'Deu 19'], [173, 5, 20, 'Deuteronomy 20', 'Deu 20'], [174, 5, 21, 'Deuteronomy 21', 'Deu 21'], [175, 5, 22, 'Deuteronomy 22', 'Deu 22'], [176, 5, 23, 'Deuteronomy 23', 'Deu 23'], [177, 5, 24, 'Deuteronomy 24', 'Deu 24'], [178, 5, 25, 'Deuteronomy 25', 'Deu 25'], [179, 5, 26, 'Deuteronomy 26', 'Deu 26'], [180, 5, 27, 'Deuteronomy 27', 'Deu 27'], [181, 5, 28, 'Deuteronomy 28', 'Deu 28'], [182, 5, 29, 'Deuteronomy 29', 'Deu 29'], [183, 5, 30, 'Deuteronomy 30', 'Deu 30'], [184, 5, 31, 'Deuteronomy 31', 'Deu 31'], [185, 5, 32, 'Deuteronomy 32', 'Deu 32'], [186, 5, 33, 'Deuteronomy 33', 'Deu 33'], [187, 5, 34, 'Deuteronomy 34', 'Deu 34'], [188, 6, 1, 'Joshua 1', 'Jos 1'], [189, 6, 2, 'Joshua 2', 'Jos 2'], [190, 6, 3, 'Joshua 3', 'Jos 3'], [191, 6, 4, 'Joshua 4', 'Jos 4'], [192, 6, 5, 'Joshua 5', 'Jos 5'], [193, 6, 6, 'Joshua 6', 'Jos 6'], [194, 6, 7, 'Joshua 7', 'Jos 7'], [195, 6, 8, 'Joshua 8', 'Jos 8'], [196, 6, 9, 'Joshua 9', 'Jos 9'], [197, 6, 10, 'Joshua 10', 'Jos 10'], [198, 6, 11, 'Joshua 11', 'Jos 11'], [199, 6, 12, 'Joshua 12', 'Jos 12'], [200, 6, 13, 'Joshua 13', 'Jos 13'], [201, 6, 14, 'Joshua 14', 'Jos 14'], [202, 6, 15, 'Joshua 15', 'Jos 15'], [203, 6, 16, 'Joshua 16', 'Jos 16'], [204, 6, 17, 'Joshua 17', 'Jos 17'], [205, 6, 18, 'Joshua 18', 'Jos 18'], [206, 6, 19, 'Joshua 19', 'Jos 19'], [207, 6, 20, 'Joshua 20', 'Jos 20'], [208, 6, 21, 'Joshua 21', 'Jos 21'], [209, 6, 22, 'Joshua 22', 'Jos 22'], [210, 6, 23, 'Joshua 23', 'Jos 23'], [211, 6, 24, 'Joshua 24', 'Jos 24'], [212, 7, 1, 'Judges 1', 'Jud 1'], [213, 7, 2, 'Judges 2', 'Jud 2'], [214, 7, 3, 'Judges 3', 'Jud 3'], [215, 7, 4, 'Judges 4', 'Jud 4'], [216, 7, 5, 'Judges 5', 'Jud 5'], [217, 7, 6, 'Judges 6', 'Jud 6'], [218, 7, 7, 'Judges 7', 'Jud 7'], [219, 7, 8, 'Judges 8', 'Jud 8'], [220, 7, 9, 'Judges 9', 'Jud 9'], [221, 7, 10, 'Judges 10', 'Jud 10'], [222, 7, 11, 'Judges 11', 'Jud 11'], [223, 7, 12, 'Judges 12', 'Jud 12'], [224, 7, 13, 'Judges 13', 'Jud 13'], [225, 7, 14, 'Judges 14', 'Jud 14'], [226, 7, 15, 'Judges 15', 'Jud 15'], [227, 7, 16, 'Judges 16', 'Jud 16'], [228, 7, 17, 'Judges 17', 'Jud 17'], [229, 7, 18, 'Judges 18', 'Jud 18'], [230, 7, 19, 'Judges 19', 'Jud 19'], [231, 7, 20, 'Judges 20', 'Jud 20'], [232, 7, 21, 'Judges 21', 'Jud 21'], [233, 8, 1, 'Ruth 1', 'Rut 1'], [234, 8, 2, 'Ruth 2', 'Rut 2'], [235, 8, 3, 'Ruth 3', 'Rut 3'], [236, 8, 4, 'Ruth 4', 'Rut 4'], [237, 9, 1, '1 Samuel 1', '1 Sam 1'], [238, 9, 2, '1 Samuel 2', '1 Sam 2'], [239, 9, 3, '1 Samuel 3', '1 Sam 3'], [240, 9, 4, '1 Samuel 4', '1 Sam 4'], [241, 9, 5, '1 Samuel 5', '1 Sam 5'], [242, 9, 6, '1 Samuel 6', '1 Sam 6'], [243, 9, 7, '1 Samuel 7', '1 Sam 7'], [244, 9, 8, '1 Samuel 8', '1 Sam 8'], [245, 9, 9, '1 Samuel 9', '1 Sam 9'], [246, 9, 10, '1 Samuel 10', '1 Sam 10'], [247, 9, 11, '1 Samuel 11', '1 Sam 11'], [248, 9, 12, '1 Samuel 12', '1 Sam 12'], [249, 9, 13, '1 Samuel 13', '1 Sam 13'], [250, 9, 14, '1 Samuel 14', '1 Sam 14'], [251, 9, 15, '1 Samuel 15', '1 Sam 15'], [252, 9, 16, '1 Samuel 16', '1 Sam 16'], [253, 9, 17, '1 Samuel 17', '1 Sam 17'], [254, 9, 18, '1 Samuel 18', '1 Sam 18'], [255, 9, 19, '1 Samuel 19', '1 Sam 19'], [256, 9, 20, '1 Samuel 20', '1 Sam 20'], [257, 9, 21, '1 Samuel 21', '1 Sam 21'], [258, 9, 22, '1 Samuel 22', '1 Sam 22'], [259, 9, 23, '1 Samuel 23', '1 Sam 23'], [260, 9, 24, '1 Samuel 24', '1 Sam 24'], [261, 9, 25, '1 Samuel 25', '1 Sam 25'], [262, 9, 26, '1 Samuel 26', '1 Sam 26'], [263, 9, 27, '1 Samuel 27', '1 Sam 27'], [264, 9, 28, '1 Samuel 28', '1 Sam 28'], [265, 9, 29, '1 Samuel 29', '1 Sam 29'], [266, 9, 30, '1 Samuel 30', '1 Sam 30'], [267, 9, 31, '1 Samuel 31', '1 Sam 31'], [268, 10, 1, '2 Samuel 1', '2 Sam 1'], [269, 10, 2, '2 Samuel 2', '2 Sam 2'], [270, 10, 3, '2 Samuel 3', '2 Sam 3'], [271, 10, 4, '2 Samuel 4', '2 Sam 4'], [272, 10, 5, '2 Samuel 5', '2 Sam 5'], [273, 10, 6, '2 Samuel 6', '2 Sam 6'], [274, 10, 7, '2 Samuel 7', '2 Sam 7'], [275, 10, 8, '2 Samuel 8', '2 Sam 8'], [276, 10, 9, '2 Samuel 9', '2 Sam 9'], [277, 10, 10, '2 Samuel 10', '2 Sam 10'], [278, 10, 11, '2 Samuel 11', '2 Sam 11'], [279, 10, 12, '2 Samuel 12', '2 Sam 12'], [280, 10, 13, '2 Samuel 13', '2 Sam 13'], [281, 10, 14, '2 Samuel 14', '2 Sam 14'], [282, 10, 15, '2 Samuel 15', '2 Sam 15'], [283, 10, 16, '2 Samuel 16', '2 Sam 16'], [284, 10, 17, '2 Samuel 17', '2 Sam 17'], [285, 10, 18, '2 Samuel 18', '2 Sam 18'], [286, 10, 19, '2 Samuel 19', '2 Sam 19'], [287, 10, 20, '2 Samuel 20', '2 Sam 20'], [288, 10, 21, '2 Samuel 21', '2 Sam 21'], [289, 10, 22, '2 Samuel 22', '2 Sam 22'], [290, 10, 23, '2 Samuel 23', '2 Sam 23'], [291, 10, 24, '2 Samuel 24', '2 Sam 24'], [292, 11, 1, '1 Kings 1', '1 Kin 1'], [293, 11, 2, '1 Kings 2', '1 Kin 2'], [294, 11, 3, '1 Kings 3', '1 Kin 3'], [295, 11, 4, '1 Kings 4', '1 Kin 4'], [296, 11, 5, '1 Kings 5', '1 Kin 5'], [297, 11, 6, '1 Kings 6', '1 Kin 6'], [298, 11, 7, '1 Kings 7', '1 Kin 7'], [299, 11, 8, '1 Kings 8', '1 Kin 8'], [300, 11, 9, '1 Kings 9', '1 Kin 9'], [301, 11, 10, '1 Kings 10', '1 Kin 10'], [302, 11, 11, '1 Kings 11', '1 Kin 11'], [303, 11, 12, '1 Kings 12', '1 Kin 12'], [304, 11, 13, '1 Kings 13', '1 Kin 13'], [305, 11, 14, '1 Kings 14', '1 Kin 14'], [306, 11, 15, '1 Kings 15', '1 Kin 15'], [307, 11, 16, '1 Kings 16', '1 Kin 16'], [308, 11, 17, '1 Kings 17', '1 Kin 17'], [309, 11, 18, '1 Kings 18', '1 Kin 18'], [310, 11, 19, '1 Kings 19', '1 Kin 19'], [311, 11, 20, '1 Kings 20', '1 Kin 20'], [312, 11, 21, '1 Kings 21', '1 Kin 21'], [313, 11, 22, '1 Kings 22', '1 Kin 22'], [314, 12, 1, '2 Kings 1', '2 Kin 1'], [315, 12, 2, '2 Kings 2', '2 Kin 2'], [316, 12, 3, '2 Kings 3', '2 Kin 3'], [317, 12, 4, '2 Kings 4', '2 Kin 4'], [318, 12, 5, '2 Kings 5', '2 Kin 5'], [319, 12, 6, '2 Kings 6', '2 Kin 6'], [320, 12, 7, '2 Kings 7', '2 Kin 7'], [321, 12, 8, '2 Kings 8', '2 Kin 8'], [322, 12, 9, '2 Kings 9', '2 Kin 9'], [323, 12, 10, '2 Kings 10', '2 Kin 10'], [324, 12, 11, '2 Kings 11', '2 Kin 11'], [325, 12, 12, '2 Kings 12', '2 Kin 12'], [326, 12, 13, '2 Kings 13', '2 Kin 13'], [327, 12, 14, '2 Kings 14', '2 Kin 14'], [328, 12, 15, '2 Kings 15', '2 Kin 15'], [329, 12, 16, '2 Kings 16', '2 Kin 16'], [330, 12, 17, '2 Kings 17', '2 Kin 17'], [331, 12, 18, '2 Kings 18', '2 Kin 18'], [332, 12, 19, '2 Kings 19', '2 Kin 19'], [333, 12, 20, '2 Kings 20', '2 Kin 20'], [334, 12, 21, '2 Kings 21', '2 Kin 21'], [335, 12, 22, '2 Kings 22', '2 Kin 22'], [336, 12, 23, '2 Kings 23', '2 Kin 23'], [337, 12, 24, '2 Kings 24', '2 Kin 24'], [338, 12, 25, '2 Kings 25', '2 Kin 25'], [339, 13, 1, '1 Chronicles 1', '1 Chr 1'], [340, 13, 2, '1 Chronicles 2', '1 Chr 2'], [341, 13, 3, '1 Chronicles 3', '1 Chr 3'], [342, 13, 4, '1 Chronicles 4', '1 Chr 4'], [343, 13, 5, '1 Chronicles 5', '1 Chr 5'], [344, 13, 6, '1 Chronicles 6', '1 Chr 6'], [345, 13, 7, '1 Chronicles 7', '1 Chr 7'], [346, 13, 8, '1 Chronicles 8', '1 Chr 8'], [347, 13, 9, '1 Chronicles 9', '1 Chr 9'], [348, 13, 10, '1 Chronicles 10', '1 Chr 10'], [349, 13, 11, '1 Chronicles 11', '1 Chr 11'], [350, 13, 12, '1 Chronicles 12', '1 Chr 12'], [351, 13, 13, '1 Chronicles 13', '1 Chr 13'], [352, 13, 14, '1 Chronicles 14', '1 Chr 14'], [353, 13, 15, '1 Chronicles 15', '1 Chr 15'], [354, 13, 16, '1 Chronicles 16', '1 Chr 16'], [355, 13, 17, '1 Chronicles 17', '1 Chr 17'], [356, 13, 18, '1 Chronicles 18', '1 Chr 18'], [357, 13, 19, '1 Chronicles 19', '1 Chr 19'], [358, 13, 20, '1 Chronicles 20', '1 Chr 20'], [359, 13, 21, '1 Chronicles 21', '1 Chr 21'], [360, 13, 22, '1 Chronicles 22', '1 Chr 22'], [361, 13, 23, '1 Chronicles 23', '1 Chr 23'], [362, 13, 24, '1 Chronicles 24', '1 Chr 24'], [363, 13, 25, '1 Chronicles 25', '1 Chr 25'], [364, 13, 26, '1 Chronicles 26', '1 Chr 26'], [365, 13, 27, '1 Chronicles 27', '1 Chr 27'], [366, 13, 28, '1 Chronicles 28', '1 Chr 28'], [367, 13, 29, '1 Chronicles 29', '1 Chr 29'], [368, 14, 1, '2 Chronicles 1', '2 Chr 1'], [369, 14, 2, '2 Chronicles 2', '2 Chr 2'], [370, 14, 3, '2 Chronicles 3', '2 Chr 3'], [371, 14, 4, '2 Chronicles 4', '2 Chr 4'], [372, 14, 5, '2 Chronicles 5', '2 Chr 5'], [373, 14, 6, '2 Chronicles 6', '2 Chr 6'], [374, 14, 7, '2 Chronicles 7', '2 Chr 7'], [375, 14, 8, '2 Chronicles 8', '2 Chr 8'], [376, 14, 9, '2 Chronicles 9', '2 Chr 9'], [377, 14, 10, '2 Chronicles 10', '2 Chr 10'], [378, 14, 11, '2 Chronicles 11', '2 Chr 11'], [379, 14, 12, '2 Chronicles 12', '2 Chr 12'], [380, 14, 13, '2 Chronicles 13', '2 Chr 13'], [381, 14, 14, '2 Chronicles 14', '2 Chr 14'], [382, 14, 15, '2 Chronicles 15', '2 Chr 15'], [383, 14, 16, '2 Chronicles 16', '2 Chr 16'], [384, 14, 17, '2 Chronicles 17', '2 Chr 17'], [385, 14, 18, '2 Chronicles 18', '2 Chr 18'], [386, 14, 19, '2 Chronicles 19', '2 Chr 19'], [387, 14, 20, '2 Chronicles 20', '2 Chr 20'], [388, 14, 21, '2 Chronicles 21', '2 Chr 21'], [389, 14, 22, '2 Chronicles 22', '2 Chr 22'], [390, 14, 23, '2 Chronicles 23', '2 Chr 23'], [391, 14, 24, '2 Chronicles 24', '2 Chr 24'], [392, 14, 25, '2 Chronicles 25', '2 Chr 25'], [393, 14, 26, '2 Chronicles 26', '2 Chr 26'], [394, 14, 27, '2 Chronicles 27', '2 Chr 27'], [395, 14, 28, '2 Chronicles 28', '2 Chr 28'], [396, 14, 29, '2 Chronicles 29', '2 Chr 29'], [397, 14, 30, '2 Chronicles 30', '2 Chr 30'], [398, 14, 31, '2 Chronicles 31', '2 Chr 31'], [399, 14, 32, '2 Chronicles 32', '2 Chr 32'], [400, 14, 33, '2 Chronicles 33', '2 Chr 33'], [401, 14, 34, '2 Chronicles 34', '2 Chr 34'], [402, 14, 35, '2 Chronicles 35', '2 Chr 35'], [403, 14, 36, '2 Chronicles 36', '2 Chr 36'], [404, 15, 1, 'Ezra 1', 'Ezr 1'], [405, 15, 2, 'Ezra 2', 'Ezr 2'], [406, 15, 3, 'Ezra 3', 'Ezr 3'], [407, 15, 4, 'Ezra 4', 'Ezr 4'], [408, 15, 5, 'Ezra 5', 'Ezr 5'], [409, 15, 6, 'Ezra 6', 'Ezr 6'], [410, 15, 7, 'Ezra 7', 'Ezr 7'], [411, 15, 8, 'Ezra 8', 'Ezr 8'], [412, 15, 9, 'Ezra 9', 'Ezr 9'], [413, 15, 10, 'Ezra 10', 'Ezr 10'], [414, 16, 1, 'Nehemiah 1', 'Neh 1'], [415, 16, 2, 'Nehemiah 2', 'Neh 2'], [416, 16, 3, 'Nehemiah 3', 'Neh 3'], [417, 16, 4, 'Nehemiah 4', 'Neh 4'], [418, 16, 5, 'Nehemiah 5', 'Neh 5'], [419, 16, 6, 'Nehemiah 6', 'Neh 6'], [420, 16, 7, 'Nehemiah 7', 'Neh 7'], [421, 16, 8, 'Nehemiah 8', 'Neh 8'], [422, 16, 9, 'Nehemiah 9', 'Neh 9'], [423, 16, 10, 'Nehemiah 10', 'Neh 10'], [424, 16, 11, 'Nehemiah 11', 'Neh 11'], [425, 16, 12, 'Nehemiah 12', 'Neh 12'], [426, 16, 13, 'Nehemiah 13', 'Neh 13'], [427, 17, 1, 'Esther 1', 'Est 1'], [428, 17, 2, 'Esther 2', 'Est 2'], [429, 17, 3, 'Esther 3', 'Est 3'], [430, 17, 4, 'Esther 4', 'Est 4'], [431, 17, 5, 'Esther 5', 'Est 5'], [432, 17, 6, 'Esther 6', 'Est 6'], [433, 17, 7, 'Esther 7', 'Est 7'], [434, 17, 8, 'Esther 8', 'Est 8'], [435, 17, 9, 'Esther 9', 'Est 9'], [436, 17, 10, 'Esther 10', 'Est 10'], [437, 18, 1, 'Job 1', 'Job 1'], [438, 18, 2, 'Job 2', 'Job 2'], [439, 18, 3, 'Job 3', 'Job 3'], [440, 18, 4, 'Job 4', 'Job 4'], [441, 18, 5, 'Job 5', 'Job 5'], [442, 18, 6, 'Job 6', 'Job 6'], [443, 18, 7, 'Job 7', 'Job 7'], [444, 18, 8, 'Job 8', 'Job 8'], [445, 18, 9, 'Job 9', 'Job 9'], [446, 18, 10, 'Job 10', 'Job 10'], [447, 18, 11, 'Job 11', 'Job 11'], [448, 18, 12, 'Job 12', 'Job 12'], [449, 18, 13, 'Job 13', 'Job 13'], [450, 18, 14, 'Job 14', 'Job 14'], [451, 18, 15, 'Job 15', 'Job 15'], [452, 18, 16, 'Job 16', 'Job 16'], [453, 18, 17, 'Job 17', 'Job 17'], [454, 18, 18, 'Job 18', 'Job 18'], [455, 18, 19, 'Job 19', 'Job 19'], [456, 18, 20, 'Job 20', 'Job 20'], [457, 18, 21, 'Job 21', 'Job 21'], [458, 18, 22, 'Job 22', 'Job 22'], [459, 18, 23, 'Job 23', 'Job 23'], [460, 18, 24, 'Job 24', 'Job 24'], [461, 18, 25, 'Job 25', 'Job 25'], [462, 18, 26, 'Job 26', 'Job 26'], [463, 18, 27, 'Job 27', 'Job 27'], [464, 18, 28, 'Job 28', 'Job 28'], [465, 18, 29, 'Job 29', 'Job 29'], [466, 18, 30, 'Job 30', 'Job 30'], [467, 18, 31, 'Job 31', 'Job 31'], [468, 18, 32, 'Job 32', 'Job 32'], [469, 18, 33, 'Job 33', 'Job 33'], [470, 18, 34, 'Job 34', 'Job 34'], [471, 18, 35, 'Job 35', 'Job 35'], [472, 18, 36, 'Job 36', 'Job 36'], [473, 18, 37, 'Job 37', 'Job 37'], [474, 18, 38, 'Job 38', 'Job 38'], [475, 18, 39, 'Job 39', 'Job 39'], [476, 18, 40, 'Job 40', 'Job 40'], [477, 18, 41, 'Job 41', 'Job 41'], [478, 18, 42, 'Job 42', 'Job 42'], [479, 19, 1, 'Psalms 1', 'Psa 1'], [480, 19, 2, 'Psalms 2', 'Psa 2'], [481, 19, 3, 'Psalms 3', 'Psa 3'], [482, 19, 4, 'Psalms 4', 'Psa 4'], [483, 19, 5, 'Psalms 5', 'Psa 5'], [484, 19, 6, 'Psalms 6', 'Psa 6'], [485, 19, 7, 'Psalms 7', 'Psa 7'], [486, 19, 8, 'Psalms 8', 'Psa 8'], [487, 19, 9, 'Psalms 9', 'Psa 9'], [488, 19, 10, 'Psalms 10', 'Psa 10'], [489, 19, 11, 'Psalms 11', 'Psa 11'], [490, 19, 12, 'Psalms 12', 'Psa 12'], [491, 19, 13, 'Psalms 13', 'Psa 13'], [492, 19, 14, 'Psalms 14', 'Psa 14'], [493, 19, 15, 'Psalms 15', 'Psa 15'], [494, 19, 16, 'Psalms 16', 'Psa 16'], [495, 19, 17, 'Psalms 17', 'Psa 17'], [496, 19, 18, 'Psalms 18', 'Psa 18'], [497, 19, 19, 'Psalms 19', 'Psa 19'], [498, 19, 20, 'Psalms 20', 'Psa 20'], [499, 19, 21, 'Psalms 21', 'Psa 21'], [500, 19, 22, 'Psalms 22', 'Psa 22'], [501, 19, 23, 'Psalms 23', 'Psa 23'], [502, 19, 24, 'Psalms 24', 'Psa 24'], [503, 19, 25, 'Psalms 25', 'Psa 25'], [504, 19, 26, 'Psalms 26', 'Psa 26'], [505, 19, 27, 'Psalms 27', 'Psa 27'], [506, 19, 28, 'Psalms 28', 'Psa 28'], [507, 19, 29, 'Psalms 29', 'Psa 29'], [508, 19, 30, 'Psalms 30', 'Psa 30'], [509, 19, 31, 'Psalms 31', 'Psa 31'], [510, 19, 32, 'Psalms 32', 'Psa 32'], [511, 19, 33, 'Psalms 33', 'Psa 33'], [512, 19, 34, 'Psalms 34', 'Psa 34'], [513, 19, 35, 'Psalms 35', 'Psa 35'], [514, 19, 36, 'Psalms 36', 'Psa 36'], [515, 19, 37, 'Psalms 37', 'Psa 37'], [516, 19, 38, 'Psalms 38', 'Psa 38'], [517, 19, 39, 'Psalms 39', 'Psa 39'], [518, 19, 40, 'Psalms 40', 'Psa 40'], [519, 19, 41, 'Psalms 41', 'Psa 41'], [520, 19, 42, 'Psalms 42', 'Psa 42'], [521, 19, 43, 'Psalms 43', 'Psa 43'], [522, 19, 44, 'Psalms 44', 'Psa 44'], [523, 19, 45, 'Psalms 45', 'Psa 45'], [524, 19, 46, 'Psalms 46', 'Psa 46'], [525, 19, 47, 'Psalms 47', 'Psa 47'], [526, 19, 48, 'Psalms 48', 'Psa 48'], [527, 19, 49, 'Psalms 49', 'Psa 49'], [528, 19, 50, 'Psalms 50', 'Psa 50'], [529, 19, 51, 'Psalms 51', 'Psa 51'], [530, 19, 52, 'Psalms 52', 'Psa 52'], [531, 19, 53, 'Psalms 53', 'Psa 53'], [532, 19, 54, 'Psalms 54', 'Psa 54'], [533, 19, 55, 'Psalms 55', 'Psa 55'], [534, 19, 56, 'Psalms 56', 'Psa 56'], [535, 19, 57, 'Psalms 57', 'Psa 57'], [536, 19, 58, 'Psalms 58', 'Psa 58'], [537, 19, 59, 'Psalms 59', 'Psa 59'], [538, 19, 60, 'Psalms 60', 'Psa 60'], [539, 19, 61, 'Psalms 61', 'Psa 61'], [540, 19, 62, 'Psalms 62', 'Psa 62'], [541, 19, 63, 'Psalms 63', 'Psa 63'], [542, 19, 64, 'Psalms 64', 'Psa 64'], [543, 19, 65, 'Psalms 65', 'Psa 65'], [544, 19, 66, 'Psalms 66', 'Psa 66'], [545, 19, 67, 'Psalms 67', 'Psa 67'], [546, 19, 68, 'Psalms 68', 'Psa 68'], [547, 19, 69, 'Psalms 69', 'Psa 69'], [548, 19, 70, 'Psalms 70', 'Psa 70'], [549, 19, 71, 'Psalms 71', 'Psa 71'], [550, 19, 72, 'Psalms 72', 'Psa 72'], [551, 19, 73, 'Psalms 73', 'Psa 73'], [552, 19, 74, 'Psalms 74', 'Psa 74'], [553, 19, 75, 'Psalms 75', 'Psa 75'], [554, 19, 76, 'Psalms 76', 'Psa 76'], [555, 19, 77, 'Psalms 77', 'Psa 77'], [556, 19, 78, 'Psalms 78', 'Psa 78'], [557, 19, 79, 'Psalms 79', 'Psa 79'], [558, 19, 80, 'Psalms 80', 'Psa 80'], [559, 19, 81, 'Psalms 81', 'Psa 81'], [560, 19, 82, 'Psalms 82', 'Psa 82'], [561, 19, 83, 'Psalms 83', 'Psa 83'], [562, 19, 84, 'Psalms 84', 'Psa 84'], [563, 19, 85, 'Psalms 85', 'Psa 85'], [564, 19, 86, 'Psalms 86', 'Psa 86'], [565, 19, 87, 'Psalms 87', 'Psa 87'], [566, 19, 88, 'Psalms 88', 'Psa 88'], [567, 19, 89, 'Psalms 89', 'Psa 89'], [568, 19, 90, 'Psalms 90', 'Psa 90'], [569, 19, 91, 'Psalms 91', 'Psa 91'], [570, 19, 92, 'Psalms 92', 'Psa 92'], [571, 19, 93, 'Psalms 93', 'Psa 93'], [572, 19, 94, 'Psalms 94', 'Psa 94'], [573, 19, 95, 'Psalms 95', 'Psa 95'], [574, 19, 96, 'Psalms 96', 'Psa 96'], [575, 19, 97, 'Psalms 97', 'Psa 97'], [576, 19, 98, 'Psalms 98', 'Psa 98'], [577, 19, 99, 'Psalms 99', 'Psa 99'], [578, 19, 100, 'Psalms 100', 'Psa 100'], [579, 19, 101, 'Psalms 101', 'Psa 101'], [580, 19, 102, 'Psalms 102', 'Psa 102'], [581, 19, 103, 'Psalms 103', 'Psa 103'], [582, 19, 104, 'Psalms 104', 'Psa 104'], [583, 19, 105, 'Psalms 105', 'Psa 105'], [584, 19, 106, 'Psalms 106', 'Psa 106'], [585, 19, 107, 'Psalms 107', 'Psa 107'], [586, 19, 108, 'Psalms 108', 'Psa 108'], [587, 19, 109, 'Psalms 109', 'Psa 109'], [588, 19, 110, 'Psalms 110', 'Psa 110'], [589, 19, 111, 'Psalms 111', 'Psa 111'], [590, 19, 112, 'Psalms 112', 'Psa 112'], [591, 19, 113, 'Psalms 113', 'Psa 113'], [592, 19, 114, 'Psalms 114', 'Psa 114'], [593, 19, 115, 'Psalms 115', 'Psa 115'], [594, 19, 116, 'Psalms 116', 'Psa 116'], [595, 19, 117, 'Psalms 117', 'Psa 117'], [
    596, 19, 118, 'Psalms 118', 'Psa 118'], [597, 19, 119, 'Psalms 119', 'Psa 119'], [598, 19, 120, 'Psalms 120', 'Psa 120'], [599, 19, 121, 'Psalms 121', 'Psa 121'], [600, 19, 122, 'Psalms 122', 'Psa 122'], [601, 19, 123, 'Psalms 123', 'Psa 123'], [602, 19, 124, 'Psalms 124', 'Psa 124'], [603, 19, 125, 'Psalms 125', 'Psa 125'], [604, 19, 126, 'Psalms 126', 'Psa 126'], [605, 19, 127, 'Psalms 127', 'Psa 127'], [606, 19, 128, 'Psalms 128', 'Psa 128'], [607, 19, 129, 'Psalms 129', 'Psa 129'], [608, 19, 130, 'Psalms 130', 'Psa 130'], [609, 19, 131, 'Psalms 131', 'Psa 131'], [610, 19, 132, 'Psalms 132', 'Psa 132'], [611, 19, 133, 'Psalms 133', 'Psa 133'], [612, 19, 134, 'Psalms 134', 'Psa 134'], [613, 19, 135, 'Psalms 135', 'Psa 135'], [614, 19, 136, 'Psalms 136', 'Psa 136'], [615, 19, 137, 'Psalms 137', 'Psa 137'], [616, 19, 138, 'Psalms 138', 'Psa 138'], [617, 19, 139, 'Psalms 139', 'Psa 139'], [618, 19, 140, 'Psalms 140', 'Psa 140'], [619, 19, 141, 'Psalms 141', 'Psa 141'], [620, 19, 142, 'Psalms 142', 'Psa 142'], [621, 19, 143, 'Psalms 143', 'Psa 143'], [622, 19, 144, 'Psalms 144', 'Psa 144'], [623, 19, 145, 'Psalms 145', 'Psa 145'], [624, 19, 146, 'Psalms 146', 'Psa 146'], [625, 19, 147, 'Psalms 147', 'Psa 147'], [626, 19, 148, 'Psalms 148', 'Psa 148'], [627, 19, 149, 'Psalms 149', 'Psa 149'], [628, 19, 150, 'Psalms 150', 'Psa 150'], [629, 20, 1, 'Proverbs 1', 'Pro 1'], [630, 20, 2, 'Proverbs 2', 'Pro 2'], [631, 20, 3, 'Proverbs 3', 'Pro 3'], [632, 20, 4, 'Proverbs 4', 'Pro 4'], [633, 20, 5, 'Proverbs 5', 'Pro 5'], [634, 20, 6, 'Proverbs 6', 'Pro 6'], [635, 20, 7, 'Proverbs 7', 'Pro 7'], [636, 20, 8, 'Proverbs 8', 'Pro 8'], [637, 20, 9, 'Proverbs 9', 'Pro 9'], [638, 20, 10, 'Proverbs 10', 'Pro 10'], [639, 20, 11, 'Proverbs 11', 'Pro 11'], [640, 20, 12, 'Proverbs 12', 'Pro 12'], [641, 20, 13, 'Proverbs 13', 'Pro 13'], [642, 20, 14, 'Proverbs 14', 'Pro 14'], [643, 20, 15, 'Proverbs 15', 'Pro 15'], [644, 20, 16, 'Proverbs 16', 'Pro 16'], [645, 20, 17, 'Proverbs 17', 'Pro 17'], [646, 20, 18, 'Proverbs 18', 'Pro 18'], [647, 20, 19, 'Proverbs 19', 'Pro 19'], [648, 20, 20, 'Proverbs 20', 'Pro 20'], [649, 20, 21, 'Proverbs 21', 'Pro 21'], [650, 20, 22, 'Proverbs 22', 'Pro 22'], [651, 20, 23, 'Proverbs 23', 'Pro 23'], [652, 20, 24, 'Proverbs 24', 'Pro 24'], [653, 20, 25, 'Proverbs 25', 'Pro 25'], [654, 20, 26, 'Proverbs 26', 'Pro 26'], [655, 20, 27, 'Proverbs 27', 'Pro 27'], [656, 20, 28, 'Proverbs 28', 'Pro 28'], [657, 20, 29, 'Proverbs 29', 'Pro 29'], [658, 20, 30, 'Proverbs 30', 'Pro 30'], [659, 20, 31, 'Proverbs 31', 'Pro 31'], [660, 21, 1, 'Ecclesiastes 1', 'Ecc 1'], [661, 21, 2, 'Ecclesiastes 2', 'Ecc 2'], [662, 21, 3, 'Ecclesiastes 3', 'Ecc 3'], [663, 21, 4, 'Ecclesiastes 4', 'Ecc 4'], [664, 21, 5, 'Ecclesiastes 5', 'Ecc 5'], [665, 21, 6, 'Ecclesiastes 6', 'Ecc 6'], [666, 21, 7, 'Ecclesiastes 7', 'Ecc 7'], [667, 21, 8, 'Ecclesiastes 8', 'Ecc 8'], [668, 21, 9, 'Ecclesiastes 9', 'Ecc 9'], [669, 21, 10, 'Ecclesiastes 10', 'Ecc 10'], [670, 21, 11, 'Ecclesiastes 11', 'Ecc 11'], [671, 21, 12, 'Ecclesiastes 12', 'Ecc 12'], [672, 22, 1, 'Song of Solomon 1', 'Son 1'], [673, 22, 2, 'Song of Solomon 2', 'Son 2'], [674, 22, 3, 'Song of Solomon 3', 'Son 3'], [675, 22, 4, 'Song of Solomon 4', 'Son 4'], [676, 22, 5, 'Song of Solomon 5', 'Son 5'], [677, 22, 6, 'Song of Solomon 6', 'Son 6'], [678, 22, 7, 'Song of Solomon 7', 'Son 7'], [679, 22, 8, 'Song of Solomon 8', 'Son 8'], [680, 23, 1, 'Isaiah 1', 'Isa 1'], [681, 23, 2, 'Isaiah 2', 'Isa 2'], [682, 23, 3, 'Isaiah 3', 'Isa 3'], [683, 23, 4, 'Isaiah 4', 'Isa 4'], [684, 23, 5, 'Isaiah 5', 'Isa 5'], [685, 23, 6, 'Isaiah 6', 'Isa 6'], [686, 23, 7, 'Isaiah 7', 'Isa 7'], [687, 23, 8, 'Isaiah 8', 'Isa 8'], [688, 23, 9, 'Isaiah 9', 'Isa 9'], [689, 23, 10, 'Isaiah 10', 'Isa 10'], [690, 23, 11, 'Isaiah 11', 'Isa 11'], [691, 23, 12, 'Isaiah 12', 'Isa 12'], [692, 23, 13, 'Isaiah 13', 'Isa 13'], [693, 23, 14, 'Isaiah 14', 'Isa 14'], [694, 23, 15, 'Isaiah 15', 'Isa 15'], [695, 23, 16, 'Isaiah 16', 'Isa 16'], [696, 23, 17, 'Isaiah 17', 'Isa 17'], [697, 23, 18, 'Isaiah 18', 'Isa 18'], [698, 23, 19, 'Isaiah 19', 'Isa 19'], [699, 23, 20, 'Isaiah 20', 'Isa 20'], [700, 23, 21, 'Isaiah 21', 'Isa 21'], [701, 23, 22, 'Isaiah 22', 'Isa 22'], [702, 23, 23, 'Isaiah 23', 'Isa 23'], [703, 23, 24, 'Isaiah 24', 'Isa 24'], [704, 23, 25, 'Isaiah 25', 'Isa 25'], [705, 23, 26, 'Isaiah 26', 'Isa 26'], [706, 23, 27, 'Isaiah 27', 'Isa 27'], [707, 23, 28, 'Isaiah 28', 'Isa 28'], [708, 23, 29, 'Isaiah 29', 'Isa 29'], [709, 23, 30, 'Isaiah 30', 'Isa 30'], [710, 23, 31, 'Isaiah 31', 'Isa 31'], [711, 23, 32, 'Isaiah 32', 'Isa 32'], [712, 23, 33, 'Isaiah 33', 'Isa 33'], [713, 23, 34, 'Isaiah 34', 'Isa 34'], [714, 23, 35, 'Isaiah 35', 'Isa 35'], [715, 23, 36, 'Isaiah 36', 'Isa 36'], [716, 23, 37, 'Isaiah 37', 'Isa 37'], [717, 23, 38, 'Isaiah 38', 'Isa 38'], [718, 23, 39, 'Isaiah 39', 'Isa 39'], [719, 23, 40, 'Isaiah 40', 'Isa 40'], [720, 23, 41, 'Isaiah 41', 'Isa 41'], [721, 23, 42, 'Isaiah 42', 'Isa 42'], [722, 23, 43, 'Isaiah 43', 'Isa 43'], [723, 23, 44, 'Isaiah 44', 'Isa 44'], [724, 23, 45, 'Isaiah 45', 'Isa 45'], [725, 23, 46, 'Isaiah 46', 'Isa 46'], [726, 23, 47, 'Isaiah 47', 'Isa 47'], [727, 23, 48, 'Isaiah 48', 'Isa 48'], [728, 23, 49, 'Isaiah 49', 'Isa 49'], [729, 23, 50, 'Isaiah 50', 'Isa 50'], [730, 23, 51, 'Isaiah 51', 'Isa 51'], [731, 23, 52, 'Isaiah 52', 'Isa 52'], [732, 23, 53, 'Isaiah 53', 'Isa 53'], [733, 23, 54, 'Isaiah 54', 'Isa 54'], [734, 23, 55, 'Isaiah 55', 'Isa 55'], [735, 23, 56, 'Isaiah 56', 'Isa 56'], [736, 23, 57, 'Isaiah 57', 'Isa 57'], [737, 23, 58, 'Isaiah 58', 'Isa 58'], [738, 23, 59, 'Isaiah 59', 'Isa 59'], [739, 23, 60, 'Isaiah 60', 'Isa 60'], [740, 23, 61, 'Isaiah 61', 'Isa 61'], [741, 23, 62, 'Isaiah 62', 'Isa 62'], [742, 23, 63, 'Isaiah 63', 'Isa 63'], [743, 23, 64, 'Isaiah 64', 'Isa 64'], [744, 23, 65, 'Isaiah 65', 'Isa 65'], [745, 23, 66, 'Isaiah 66', 'Isa 66'], [746, 24, 1, 'Jeremiah 1', 'Jer 1'], [747, 24, 2, 'Jeremiah 2', 'Jer 2'], [748, 24, 3, 'Jeremiah 3', 'Jer 3'], [749, 24, 4, 'Jeremiah 4', 'Jer 4'], [750, 24, 5, 'Jeremiah 5', 'Jer 5'], [751, 24, 6, 'Jeremiah 6', 'Jer 6'], [752, 24, 7, 'Jeremiah 7', 'Jer 7'], [753, 24, 8, 'Jeremiah 8', 'Jer 8'], [754, 24, 9, 'Jeremiah 9', 'Jer 9'], [755, 24, 10, 'Jeremiah 10', 'Jer 10'], [756, 24, 11, 'Jeremiah 11', 'Jer 11'], [757, 24, 12, 'Jeremiah 12', 'Jer 12'], [758, 24, 13, 'Jeremiah 13', 'Jer 13'], [759, 24, 14, 'Jeremiah 14', 'Jer 14'], [760, 24, 15, 'Jeremiah 15', 'Jer 15'], [761, 24, 16, 'Jeremiah 16', 'Jer 16'], [762, 24, 17, 'Jeremiah 17', 'Jer 17'], [763, 24, 18, 'Jeremiah 18', 'Jer 18'], [764, 24, 19, 'Jeremiah 19', 'Jer 19'], [765, 24, 20, 'Jeremiah 20', 'Jer 20'], [766, 24, 21, 'Jeremiah 21', 'Jer 21'], [767, 24, 22, 'Jeremiah 22', 'Jer 22'], [768, 24, 23, 'Jeremiah 23', 'Jer 23'], [769, 24, 24, 'Jeremiah 24', 'Jer 24'], [770, 24, 25, 'Jeremiah 25', 'Jer 25'], [771, 24, 26, 'Jeremiah 26', 'Jer 26'], [772, 24, 27, 'Jeremiah 27', 'Jer 27'], [773, 24, 28, 'Jeremiah 28', 'Jer 28'], [774, 24, 29, 'Jeremiah 29', 'Jer 29'], [775, 24, 30, 'Jeremiah 30', 'Jer 30'], [776, 24, 31, 'Jeremiah 31', 'Jer 31'], [777, 24, 32, 'Jeremiah 32', 'Jer 32'], [778, 24, 33, 'Jeremiah 33', 'Jer 33'], [779, 24, 34, 'Jeremiah 34', 'Jer 34'], [780, 24, 35, 'Jeremiah 35', 'Jer 35'], [781, 24, 36, 'Jeremiah 36', 'Jer 36'], [782, 24, 37, 'Jeremiah 37', 'Jer 37'], [783, 24, 38, 'Jeremiah 38', 'Jer 38'], [784, 24, 39, 'Jeremiah 39', 'Jer 39'], [785, 24, 40, 'Jeremiah 40', 'Jer 40'], [786, 24, 41, 'Jeremiah 41', 'Jer 41'], [787, 24, 42, 'Jeremiah 42', 'Jer 42'], [788, 24, 43, 'Jeremiah 43', 'Jer 43'], [789, 24, 44, 'Jeremiah 44', 'Jer 44'], [790, 24, 45, 'Jeremiah 45', 'Jer 45'], [791, 24, 46, 'Jeremiah 46', 'Jer 46'], [792, 24, 47, 'Jeremiah 47', 'Jer 47'], [793, 24, 48, 'Jeremiah 48', 'Jer 48'], [794, 24, 49, 'Jeremiah 49', 'Jer 49'], [795, 24, 50, 'Jeremiah 50', 'Jer 50'], [796, 24, 51, 'Jeremiah 51', 'Jer 51'], [797, 24, 52, 'Jeremiah 52', 'Jer 52'], [798, 25, 1, 'Lamentations 1', 'Lam 1'], [799, 25, 2, 'Lamentations 2', 'Lam 2'], [800, 25, 3, 'Lamentations 3', 'Lam 3'], [801, 25, 4, 'Lamentations 4', 'Lam 4'], [802, 25, 5, 'Lamentations 5', 'Lam 5'], [803, 26, 1, 'Ezekiel 1', 'Eze 1'], [804, 26, 2, 'Ezekiel 2', 'Eze 2'], [805, 26, 3, 'Ezekiel 3', 'Eze 3'], [806, 26, 4, 'Ezekiel 4', 'Eze 4'], [807, 26, 5, 'Ezekiel 5', 'Eze 5'], [808, 26, 6, 'Ezekiel 6', 'Eze 6'], [809, 26, 7, 'Ezekiel 7', 'Eze 7'], [810, 26, 8, 'Ezekiel 8', 'Eze 8'], [811, 26, 9, 'Ezekiel 9', 'Eze 9'], [812, 26, 10, 'Ezekiel 10', 'Eze 10'], [813, 26, 11, 'Ezekiel 11', 'Eze 11'], [814, 26, 12, 'Ezekiel 12', 'Eze 12'], [815, 26, 13, 'Ezekiel 13', 'Eze 13'], [816, 26, 14, 'Ezekiel 14', 'Eze 14'], [817, 26, 15, 'Ezekiel 15', 'Eze 15'], [818, 26, 16, 'Ezekiel 16', 'Eze 16'], [819, 26, 17, 'Ezekiel 17', 'Eze 17'], [820, 26, 18, 'Ezekiel 18', 'Eze 18'], [821, 26, 19, 'Ezekiel 19', 'Eze 19'], [822, 26, 20, 'Ezekiel 20', 'Eze 20'], [823, 26, 21, 'Ezekiel 21', 'Eze 21'], [824, 26, 22, 'Ezekiel 22', 'Eze 22'], [825, 26, 23, 'Ezekiel 23', 'Eze 23'], [826, 26, 24, 'Ezekiel 24', 'Eze 24'], [827, 26, 25, 'Ezekiel 25', 'Eze 25'], [828, 26, 26, 'Ezekiel 26', 'Eze 26'], [829, 26, 27, 'Ezekiel 27', 'Eze 27'], [830, 26, 28, 'Ezekiel 28', 'Eze 28'], [831, 26, 29, 'Ezekiel 29', 'Eze 29'], [832, 26, 30, 'Ezekiel 30', 'Eze 30'], [833, 26, 31, 'Ezekiel 31', 'Eze 31'], [834, 26, 32, 'Ezekiel 32', 'Eze 32'], [835, 26, 33, 'Ezekiel 33', 'Eze 33'], [836, 26, 34, 'Ezekiel 34', 'Eze 34'], [837, 26, 35, 'Ezekiel 35', 'Eze 35'], [838, 26, 36, 'Ezekiel 36', 'Eze 36'], [839, 26, 37, 'Ezekiel 37', 'Eze 37'], [840, 26, 38, 'Ezekiel 38', 'Eze 38'], [841, 26, 39, 'Ezekiel 39', 'Eze 39'], [842, 26, 40, 'Ezekiel 40', 'Eze 40'], [843, 26, 41, 'Ezekiel 41', 'Eze 41'], [844, 26, 42, 'Ezekiel 42', 'Eze 42'], [845, 26, 43, 'Ezekiel 43', 'Eze 43'], [846, 26, 44, 'Ezekiel 44', 'Eze 44'], [847, 26, 45, 'Ezekiel 45', 'Eze 45'], [848, 26, 46, 'Ezekiel 46', 'Eze 46'], [849, 26, 47, 'Ezekiel 47', 'Eze 47'], [850, 26, 48, 'Ezekiel 48', 'Eze 48'], [851, 27, 1, 'Daniel 1', 'Dan 1'], [852, 27, 2, 'Daniel 2', 'Dan 2'], [853, 27, 3, 'Daniel 3', 'Dan 3'], [854, 27, 4, 'Daniel 4', 'Dan 4'], [855, 27, 5, 'Daniel 5', 'Dan 5'], [856, 27, 6, 'Daniel 6', 'Dan 6'], [857, 27, 7, 'Daniel 7', 'Dan 7'], [858, 27, 8, 'Daniel 8', 'Dan 8'], [859, 27, 9, 'Daniel 9', 'Dan 9'], [860, 27, 10, 'Daniel 10', 'Dan 10'], [861, 27, 11, 'Daniel 11', 'Dan 11'], [862, 27, 12, 'Daniel 12', 'Dan 12'], [863, 28, 1, 'Hosea 1', 'Hos 1'], [864, 28, 2, 'Hosea 2', 'Hos 2'], [865, 28, 3, 'Hosea 3', 'Hos 3'], [866, 28, 4, 'Hosea 4', 'Hos 4'], [867, 28, 5, 'Hosea 5', 'Hos 5'], [868, 28, 6, 'Hosea 6', 'Hos 6'], [869, 28, 7, 'Hosea 7', 'Hos 7'], [870, 28, 8, 'Hosea 8', 'Hos 8'], [871, 28, 9, 'Hosea 9', 'Hos 9'], [872, 28, 10, 'Hosea 10', 'Hos 10'], [873, 28, 11, 'Hosea 11', 'Hos 11'], [874, 28, 12, 'Hosea 12', 'Hos 12'], [875, 28, 13, 'Hosea 13', 'Hos 13'], [876, 28, 14, 'Hosea 14', 'Hos 14'], [877, 29, 1, 'Joel 1', 'Joe 1'], [878, 29, 2, 'Joel 2', 'Joe 2'], [879, 29, 3, 'Joel 3', 'Joe 3'], [880, 30, 1, 'Amos 1', 'Amo 1'], [881, 30, 2, 'Amos 2', 'Amo 2'], [882, 30, 3, 'Amos 3', 'Amo 3'], [883, 30, 4, 'Amos 4', 'Amo 4'], [884, 30, 5, 'Amos 5', 'Amo 5'], [885, 30, 6, 'Amos 6', 'Amo 6'], [886, 30, 7, 'Amos 7', 'Amo 7'], [887, 30, 8, 'Amos 8', 'Amo 8'], [888, 30, 9, 'Amos 9', 'Amo 9'], [889, 31, 1, 'Obadiah 1', 'Oba 1'], [890, 32, 1, 'Jonah 1', 'Jon 1'], [891, 32, 2, 'Jonah 2', 'Jon 2'], [892, 32, 3, 'Jonah 3', 'Jon 3'], [893, 32, 4, 'Jonah 4', 'Jon 4'], [894, 33, 1, 'Micah 1', 'Mic 1'], [895, 33, 2, 'Micah 2', 'Mic 2'], [896, 33, 3, 'Micah 3', 'Mic 3'], [897, 33, 4, 'Micah 4', 'Mic 4'], [898, 33, 5, 'Micah 5', 'Mic 5'], [899, 33, 6, 'Micah 6', 'Mic 6'], [900, 33, 7, 'Micah 7', 'Mic 7'], [901, 34, 1, 'Nahum 1', 'Nah 1'], [902, 34, 2, 'Nahum 2', 'Nah 2'], [903, 34, 3, 'Nahum 3', 'Nah 3'], [904, 35, 1, 'Habakkuk 1', 'Hab 1'], [905, 35, 2, 'Habakkuk 2', 'Hab 2'], [906, 35, 3, 'Habakkuk 3', 'Hab 3'], [907, 36, 1, 'Zephaniah 1', 'Zep 1'], [908, 36, 2, 'Zephaniah 2', 'Zep 2'], [909, 36, 3, 'Zephaniah 3', 'Zep 3'], [910, 37, 1, 'Haggai 1', 'Hag 1'], [911, 37, 2, 'Haggai 2', 'Hag 2'], [912, 38, 1, 'Zechariah 1', 'Zec 1'], [913, 38, 2, 'Zechariah 2', 'Zec 2'], [914, 38, 3, 'Zechariah 3', 'Zec 3'], [915, 38, 4, 'Zechariah 4', 'Zec 4'], [916, 38, 5, 'Zechariah 5', 'Zec 5'], [917, 38, 6, 'Zechariah 6', 'Zec 6'], [918, 38, 7, 'Zechariah 7', 'Zec 7'], [919, 38, 8, 'Zechariah 8', 'Zec 8'], [920, 38, 9, 'Zechariah 9', 'Zec 9'], [921, 38, 10, 'Zechariah 10', 'Zec 10'], [922, 38, 11, 'Zechariah 11', 'Zec 11'], [923, 38, 12, 'Zechariah 12', 'Zec 12'], [924, 38, 13, 'Zechariah 13', 'Zec 13'], [925, 38, 14, 'Zechariah 14', 'Zec 14'], [926, 39, 1, 'Malachi 1', 'Mal 1'], [927, 39, 2, 'Malachi 2', 'Mal 2'], [928, 39, 3, 'Malachi 3', 'Mal 3'], [929, 39, 4, 'Malachi 4', 'Mal 4'], [930, 40, 1, 'Matthew 1', 'Mat 1'], [931, 40, 2, 'Matthew 2', 'Mat 2'], [932, 40, 3, 'Matthew 3', 'Mat 3'], [933, 40, 4, 'Matthew 4', 'Mat 4'], [934, 40, 5, 'Matthew 5', 'Mat 5'], [935, 40, 6, 'Matthew 6', 'Mat 6'], [936, 40, 7, 'Matthew 7', 'Mat 7'], [937, 40, 8, 'Matthew 8', 'Mat 8'], [938, 40, 9, 'Matthew 9', 'Mat 9'], [939, 40, 10, 'Matthew 10', 'Mat 10'], [940, 40, 11, 'Matthew 11', 'Mat 11'], [941, 40, 12, 'Matthew 12', 'Mat 12'], [942, 40, 13, 'Matthew 13', 'Mat 13'], [943, 40, 14, 'Matthew 14', 'Mat 14'], [944, 40, 15, 'Matthew 15', 'Mat 15'], [945, 40, 16, 'Matthew 16', 'Mat 16'], [946, 40, 17, 'Matthew 17', 'Mat 17'], [947, 40, 18, 'Matthew 18', 'Mat 18'], [948, 40, 19, 'Matthew 19', 'Mat 19'], [949, 40, 20, 'Matthew 20', 'Mat 20'], [950, 40, 21, 'Matthew 21', 'Mat 21'], [951, 40, 22, 'Matthew 22', 'Mat 22'], [952, 40, 23, 'Matthew 23', 'Mat 23'], [953, 40, 24, 'Matthew 24', 'Mat 24'], [954, 40, 25, 'Matthew 25', 'Mat 25'], [955, 40, 26, 'Matthew 26', 'Mat 26'], [956, 40, 27, 'Matthew 27', 'Mat 27'], [957, 40, 28, 'Matthew 28', 'Mat 28'], [958, 41, 1, 'Mark 1', 'Mar 1'], [959, 41, 2, 'Mark 2', 'Mar 2'], [960, 41, 3, 'Mark 3', 'Mar 3'], [961, 41, 4, 'Mark 4', 'Mar 4'], [962, 41, 5, 'Mark 5', 'Mar 5'], [963, 41, 6, 'Mark 6', 'Mar 6'], [964, 41, 7, 'Mark 7', 'Mar 7'], [965, 41, 8, 'Mark 8', 'Mar 8'], [966, 41, 9, 'Mark 9', 'Mar 9'], [967, 41, 10, 'Mark 10', 'Mar 10'], [968, 41, 11, 'Mark 11', 'Mar 11'], [969, 41, 12, 'Mark 12', 'Mar 12'], [970, 41, 13, 'Mark 13', 'Mar 13'], [971, 41, 14, 'Mark 14', 'Mar 14'], [972, 41, 15, 'Mark 15', 'Mar 15'], [973, 41, 16, 'Mark 16', 'Mar 16'], [974, 42, 1, 'Luke 1', 'Luk 1'], [975, 42, 2, 'Luke 2', 'Luk 2'], [976, 42, 3, 'Luke 3', 'Luk 3'], [977, 42, 4, 'Luke 4', 'Luk 4'], [978, 42, 5, 'Luke 5', 'Luk 5'], [979, 42, 6, 'Luke 6', 'Luk 6'], [980, 42, 7, 'Luke 7', 'Luk 7'], [981, 42, 8, 'Luke 8', 'Luk 8'], [982, 42, 9, 'Luke 9', 'Luk 9'], [983, 42, 10, 'Luke 10', 'Luk 10'], [984, 42, 11, 'Luke 11', 'Luk 11'], [985, 42, 12, 'Luke 12', 'Luk 12'], [986, 42, 13, 'Luke 13', 'Luk 13'], [987, 42, 14, 'Luke 14', 'Luk 14'], [988, 42, 15, 'Luke 15', 'Luk 15'], [989, 42, 16, 'Luke 16', 'Luk 16'], [990, 42, 17, 'Luke 17', 'Luk 17'], [991, 42, 18, 'Luke 18', 'Luk 18'], [992, 42, 19, 'Luke 19', 'Luk 19'], [993, 42, 20, 'Luke 20', 'Luk 20'], [994, 42, 21, 'Luke 21', 'Luk 21'], [995, 42, 22, 'Luke 22', 'Luk 22'], [996, 42, 23, 'Luke 23', 'Luk 23'], [997, 42, 24, 'Luke 24', 'Luk 24'], [998, 43, 1, 'John 1', 'Joh 1'], [999, 43, 2, 'John 2', 'Joh 2'], [1000, 43, 3, 'John 3', 'Joh 3'], [1001, 43, 4, 'John 4', 'Joh 4'], [1002, 43, 5, 'John 5', 'Joh 5'], [1003, 43, 6, 'John 6', 'Joh 6'], [1004, 43, 7, 'John 7', 'Joh 7'], [1005, 43, 8, 'John 8', 'Joh 8'], [1006, 43, 9, 'John 9', 'Joh 9'], [1007, 43, 10, 'John 10', 'Joh 10'], [1008, 43, 11, 'John 11', 'Joh 11'], [1009, 43, 12, 'John 12', 'Joh 12'], [1010, 43, 13, 'John 13', 'Joh 13'], [1011, 43, 14, 'John 14', 'Joh 14'], [1012, 43, 15, 'John 15', 'Joh 15'], [1013, 43, 16, 'John 16', 'Joh 16'], [1014, 43, 17, 'John 17', 'Joh 17'], [1015, 43, 18, 'John 18', 'Joh 18'], [1016, 43, 19, 'John 19', 'Joh 19'], [1017, 43, 20, 'John 20', 'Joh 20'], [1018, 43, 21, 'John 21', 'Joh 21'], [1019, 44, 1, 'Acts 1', 'Act 1'], [1020, 44, 2, 'Acts 2', 'Act 2'], [1021, 44, 3, 'Acts 3', 'Act 3'], [1022, 44, 4, 'Acts 4', 'Act 4'], [1023, 44, 5, 'Acts 5', 'Act 5'], [1024, 44, 6, 'Acts 6', 'Act 6'], [1025, 44, 7, 'Acts 7', 'Act 7'], [1026, 44, 8, 'Acts 8', 'Act 8'], [1027, 44, 9, 'Acts 9', 'Act 9'], [1028, 44, 10, 'Acts 10', 'Act 10'], [1029, 44, 11, 'Acts 11', 'Act 11'], [1030, 44, 12, 'Acts 12', 'Act 12'], [1031, 44, 13, 'Acts 13', 'Act 13'], [1032, 44, 14, 'Acts 14', 'Act 14'], [1033, 44, 15, 'Acts 15', 'Act 15'], [1034, 44, 16, 'Acts 16', 'Act 16'], [1035, 44, 17, 'Acts 17', 'Act 17'], [1036, 44, 18, 'Acts 18', 'Act 18'], [1037, 44, 19, 'Acts 19', 'Act 19'], [1038, 44, 20, 'Acts 20', 'Act 20'], [1039, 44, 21, 'Acts 21', 'Act 21'], [1040, 44, 22, 'Acts 22', 'Act 22'], [1041, 44, 23, 'Acts 23', 'Act 23'], [1042, 44, 24, 'Acts 24', 'Act 24'], [1043, 44, 25, 'Acts 25', 'Act 25'], [1044, 44, 26, 'Acts 26', 'Act 26'], [1045, 44, 27, 'Acts 27', 'Act 27'], [1046, 44, 28, 'Acts 28', 'Act 28'], [1047, 45, 1, 'Romans 1', 'Rom 1'], [1048, 45, 2, 'Romans 2', 'Rom 2'], [1049, 45, 3, 'Romans 3', 'Rom 3'], [1050, 45, 4, 'Romans 4', 'Rom 4'], [1051, 45, 5, 'Romans 5', 'Rom 5'], [1052, 45, 6, 'Romans 6', 'Rom 6'], [1053, 45, 7, 'Romans 7', 'Rom 7'], [1054, 45, 8, 'Romans 8', 'Rom 8'], [1055, 45, 9, 'Romans 9', 'Rom 9'], [1056, 45, 10, 'Romans 10', 'Rom 10'], [1057, 45, 11, 'Romans 11', 'Rom 11'], [1058, 45, 12, 'Romans 12', 'Rom 12'], [1059, 45, 13, 'Romans 13', 'Rom 13'], [1060, 45, 14, 'Romans 14', 'Rom 14'], [1061, 45, 15, 'Romans 15', 'Rom 15'], [1062, 45, 16, 'Romans 16', 'Rom 16'], [1063, 46, 1, '1 Corinthians 1', '1 Cor 1'], [1064, 46, 2, '1 Corinthians 2', '1 Cor 2'], [1065, 46, 3, '1 Corinthians 3', '1 Cor 3'], [1066, 46, 4, '1 Corinthians 4', '1 Cor 4'], [1067, 46, 5, '1 Corinthians 5', '1 Cor 5'], [1068, 46, 6, '1 Corinthians 6', '1 Cor 6'], [1069, 46, 7, '1 Corinthians 7', '1 Cor 7'], [1070, 46, 8, '1 Corinthians 8', '1 Cor 8'], [1071, 46, 9, '1 Corinthians 9', '1 Cor 9'], [1072, 46, 10, '1 Corinthians 10', '1 Cor 10'], [1073, 46, 11, '1 Corinthians 11', '1 Cor 11'], [1074, 46, 12, '1 Corinthians 12', '1 Cor 12'], [1075, 46, 13, '1 Corinthians 13', '1 Cor 13'], [1076, 46, 14, '1 Corinthians 14', '1 Cor 14'], [1077, 46, 15, '1 Corinthians 15', '1 Cor 15'], [1078, 46, 16, '1 Corinthians 16', '1 Cor 16'], [1079, 47, 1, '2 Corinthians 1', '2 Cor 1'], [1080, 47, 2, '2 Corinthians 2', '2 Cor 2'], [1081, 47, 3, '2 Corinthians 3', '2 Cor 3'], [1082, 47, 4, '2 Corinthians 4', '2 Cor 4'], [1083, 47, 5, '2 Corinthians 5', '2 Cor 5'], [1084, 47, 6, '2 Corinthians 6', '2 Cor 6'], [1085, 47, 7, '2 Corinthians 7', '2 Cor 7'], [1086, 47, 8, '2 Corinthians 8', '2 Cor 8'], [1087, 47, 9, '2 Corinthians 9', '2 Cor 9'], [1088, 47, 10, '2 Corinthians 10', '2 Cor 10'], [1089, 47, 11, '2 Corinthians 11', '2 Cor 11'], [1090, 47, 12, '2 Corinthians 12', '2 Cor 12'], [1091, 47, 13, '2 Corinthians 13', '2 Cor 13'], [1092, 48, 1, 'Galatians 1', 'Gal 1'], [1093, 48, 2, 'Galatians 2', 'Gal 2'], [1094, 48, 3, 'Galatians 3', 'Gal 3'], [1095, 48, 4, 'Galatians 4', 'Gal 4'], [1096, 48, 5, 'Galatians 5', 'Gal 5'], [1097, 48, 6, 'Galatians 6', 'Gal 6'], [1098, 49, 1, 'Ephesians 1', 'Eph 1'], [1099, 49, 2, 'Ephesians 2', 'Eph 2'], [1100, 49, 3, 'Ephesians 3', 'Eph 3'], [1101, 49, 4, 'Ephesians 4', 'Eph 4'], [1102, 49, 5, 'Ephesians 5', 'Eph 5'], [1103, 49, 6, 'Ephesians 6', 'Eph 6'], [1104, 50, 1, 'Philippians 1', 'Phi 1'], [1105, 50, 2, 'Philippians 2', 'Phi 2'], [1106, 50, 3, 'Philippians 3', 'Phi 3'], [1107, 50, 4, 'Philippians 4', 'Phi 4'], [1108, 51, 1, 'Colossians 1', 'Col 1'], [1109, 51, 2, 'Colossians 2', 'Col 2'], [1110, 51, 3, 'Colossians 3', 'Col 3'], [1111, 51, 4, 'Colossians 4', 'Col 4'], [1112, 52, 1, '1 Thessalonians 1', '1 The 1'], [1113, 52, 2, '1 Thessalonians 2', '1 The 2'], [1114, 52, 3, '1 Thessalonians 3', '1 The 3'], [1115, 52, 4, '1 Thessalonians 4', '1 The 4'], [1116, 52, 5, '1 Thessalonians 5', '1 The 5'], [1117, 53, 1, '2 Thessalonians 1', '2 The 1'], [1118, 53, 2, '2 Thessalonians 2', '2 The 2'], [1119, 53, 3, '2 Thessalonians 3', '2 The 3'], [1120, 54, 1, '1 Timothy 1', '1 Tim 1'], [1121, 54, 2, '1 Timothy 2', '1 Tim 2'], [1122, 54, 3, '1 Timothy 3', '1 Tim 3'], [1123, 54, 4, '1 Timothy 4', '1 Tim 4'], [1124, 54, 5, '1 Timothy 5', '1 Tim 5'], [1125, 54, 6, '1 Timothy 6', '1 Tim 6'], [1126, 55, 1, '2 Timothy 1', '2 Tim 1'], [1127, 55, 2, '2 Timothy 2', '2 Tim 2'], [1128, 55, 3, '2 Timothy 3', '2 Tim 3'], [1129, 55, 4, '2 Timothy 4', '2 Tim 4'], [1130, 56, 1, 'Titus 1', 'Tit 1'], [1131, 56, 2, 'Titus 2', 'Tit 2'], [1132, 56, 3, 'Titus 3', 'Tit 3'], [1133, 57, 1, 'Philemon 1', 'Phi 1'], [1134, 58, 1, 'Hebrews 1', 'Heb 1'], [1135, 58, 2, 'Hebrews 2', 'Heb 2'], [1136, 58, 3, 'Hebrews 3', 'Heb 3'], [1137, 58, 4, 'Hebrews 4', 'Heb 4'], [1138, 58, 5, 'Hebrews 5', 'Heb 5'], [1139, 58, 6, 'Hebrews 6', 'Heb 6'], [1140, 58, 7, 'Hebrews 7', 'Heb 7'], [1141, 58, 8, 'Hebrews 8', 'Heb 8'], [1142, 58, 9, 'Hebrews 9', 'Heb 9'], [1143, 58, 10, 'Hebrews 10', 'Heb 10'], [1144, 58, 11, 'Hebrews 11', 'Heb 11'], [1145, 58, 12, 'Hebrews 12', 'Heb 12'], [1146, 58, 13, 'Hebrews 13', 'Heb 13'], [1147, 59, 1, 'James 1', 'Jam 1'], [1148, 59, 2, 'James 2', 'Jam 2'], [1149, 59, 3, 'James 3', 'Jam 3'], [1150, 59, 4, 'James 4', 'Jam 4'], [1151, 59, 5, 'James 5', 'Jam 5'], [1152, 60, 1, '1 Peter 1', '1 Pet 1'], [1153, 60, 2, '1 Peter 2', '1 Pet 2'], [1154, 60, 3, '1 Peter 3', '1 Pet 3'], [1155, 60, 4, '1 Peter 4', '1 Pet 4'], [1156, 60, 5, '1 Peter 5', '1 Pet 5'], [1157, 61, 1, '2 Peter 1', '2 Pet 1'], [1158, 61, 2, '2 Peter 2', '2 Pet 2'], [1159, 61, 3, '2 Peter 3', '2 Pet 3'], [1160, 62, 1, '1 John 1', '1 Joh 1'], [1161, 62, 2, '1 John 2', '1 Joh 2'], [1162, 62, 3, '1 John 3', '1 Joh 3'], [1163, 62, 4, '1 John 4', '1 Joh 4'], [1164, 62, 5, '1 John 5', '1 Joh 5'], [1165, 63, 1, '2 John 1', '2 Joh 1'], [1166, 64, 1, '3 John 1', '3 Joh 1'], [1167, 65, 1, 'Jude 1', 'Jud 1'], [1168, 66, 1, 'Revelation 1', 'Rev 1'], [1169, 66, 2, 'Revelation 2', 'Rev 2'], [1170, 66, 3, 'Revelation 3', 'Rev 3'], [1171, 66, 4, 'Revelation 4', 'Rev 4'], [1172, 66, 5, 'Revelation 5', 'Rev 5'], [1173, 66, 6, 'Revelation 6', 'Rev 6'], [1174, 66, 7, 'Revelation 7', 'Rev 7'], [1175, 66, 8, 'Revelation 8', 'Rev 8'], [1176, 66, 9, 'Revelation 9', 'Rev 9'], [1177, 66, 10, 'Revelation 10', 'Rev 10'], [1178, 66, 11, 'Revelation 11', 'Rev 11'], [1179, 66, 12, 'Revelation 12', 'Rev 12'], [1180, 66, 13, 'Revelation 13', 'Rev 13'], [1181, 66, 14, 'Revelation 14', 'Rev 14'], [1182, 66, 15, 'Revelation 15', 'Rev 15'], [1183, 66, 16, 'Revelation 16', 'Rev 16'], [1184, 66, 17, 'Revelation 17', 'Rev 17'], [1185, 66, 18, 'Revelation 18', 'Rev 18'], [1186, 66, 19, 'Revelation 19', 'Rev 19'], [1187, 66, 20, 'Revelation 20', 'Rev 20'], [1188, 66, 21, 'Revelation 21', 'Rev 21'], [1189, 66, 22, 'Revelation 22', 'Rev 22']]


@app.route('/bible')
def bible():
    global result_list
    if 'username' in session:
        login = True
        user = session['username']
    else:
        login = False
        user = ""

    return render_template("bible.html", login=login, user=user, rows=result_list)


def bible_db(db_val, selected_id):
    dbs = ['kjv.db', 'hindi_unicode.db', 'tamil.db', 'telugu.db']
    conn = sqlite3.connect(dbs[db_val])
    cursor = conn.cursor()
    bookNum = result_list[selected_id][1]
    chNum = result_list[selected_id][2]
    # Execute a query to select data from the 'songs' table for the selected ID
    cursor.execute(
        'SELECT * FROM words WHERE bookNum = ? AND chNum = ?', (bookNum, chNum,))
    row = cursor.fetchall()
    conn.close()
    return row


@app.route('/get_verse', methods=['POST'])
def get_verse():
    global result_list
    data = request.get_json()
    selected_id = int(data['id']) - 1
    # print("data", result_list[selected_id])
    language = int(data['language'])
    split = int(data['split'])

    if split == 0:
        row = bible_db(language, selected_id)
        lyrics = ""
        if row:
            for i in (row):
                # print(row[i][1])
                lyrics += f"<p id={i[4]} style='border: 1px solid black;padding: 10px;'>" + "<span style='font-weight:bold;font-size:larger;'>" + \
                    result_list[selected_id][3] + ":" + \
                    str(i[4]) + "</span><br>" + i[1] + "</p>"

            # print(lyrics)
            return jsonify({'lyrics': lyrics, 'title': result_list[selected_id][3]})
        else:
            return jsonify({'lyrics': [], 'title': []})

    if split == 1:
        row = bible_db(0, selected_id)
        row1 = bible_db(language, selected_id)
        lyrics = ""
        if row:
            for i in range(len(row)):
                # print(row[i][1])
                lyrics += f"<p id={row[i][4]} style='border: 1px solid black;padding: 10px;'>" + "<span style='font-weight:bold;font-size:larger;'>" + \
                    result_list[selected_id][3] + ":" + str(
                        row[i][4]) + "</span><br>" + row[i][1] + f"<br><span style='color:green;'>{row1[i][1]}</span></p>"

            # print(lyrics)
            return jsonify({'lyrics': lyrics, 'title': result_list[selected_id][3]})
        else:
            return jsonify({'lyrics': [], 'title': []})

    if split == 2:
        row = bible_db(0, selected_id)
        row1 = bible_db(language, selected_id)
        lyrics = ""
        if row:
            for i in range(len(row)):
                # print(row[i][1])
                lyrics += f"<p id={row[i][4]} style='border: 1px solid black;padding: 10px;'>" + "<span style='font-weight:bold;font-size:larger;'>" + result_list[selected_id][3] + ":" + str(
                    row[i][4]) + "</span><br>" + row[i][1] + "</p>" + f"<p id={row[i][4]} style='border: 1px solid black;padding: 10px;'>" + "<span style='font-weight:bold;font-size:larger;'>" + result_list[selected_id][3] + ":" + str(row[i][4]) + "</span><br>" + f"<span style='color:green;'>{row1[i][1]}</span></p>"

            # print(lyrics)
            return jsonify({'lyrics': lyrics, 'title': result_list[selected_id][3]})
        else:
            return jsonify({'lyrics': [], 'title': []})


@app.route('/admincontrol')
def admin_dashboard():
    try:
        if 'username' not in session and session['username'] != "samjose":
            return "Not Authorized"

        conn=create_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * from users')
        rows = cursor.fetchall()

        conn.close()

        return render_template("admin_dashboard.html", users=rows)
    except:
        return "Login as Admin"


@app.route('/modify_user/<int:user_id>')
def modify_user(user_id):
    # Fetch user data by user_id and perform modification logic here
    conn = create_connection()
    cursor = conn.cursor()

    # Fetch the current permission value
    cursor.execute('SELECT permission FROM users WHERE id = ?', (user_id,))
    current_permission = cursor.fetchone()[0]

    # Increment permission, reset to 0 if it exceeds 3
    new_permission = (current_permission + 1) % 4

    # Update the permission in the database
    cursor.execute('UPDATE users SET permission = ? WHERE id = ?', (new_permission, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))



@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session and session['username'] != "samjose":
        return "Not Authorized"

    # Logic to delete user
    conn=create_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()

    conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/get_lyrics', methods=['POST'])
def get_lyrics():
    data = request.get_json()
    selected_id = data['id']
    # print("ids", selected_id)

    # Connect to the SQLite database
    conn = create_connection()
    cursor = conn.cursor()

    # Execute a query to select data from the 'songs' table for the selected ID
    # This line has been modified to be vulnerable to SQL injection
    query = f"SELECT lyrics, transliteration, chord, title FROM songs WHERE id = {selected_id}"
    cursor.execute(query)

    row = cursor.fetchone()
    # print(row)

    # Close the database connection
    conn.close()
    print(row)
    if row:
        lyrics = song_view(row[0], sanitize_html(row[1]), sanitize_html(row[2]))
        # print(lyrics)
        return jsonify({'lyrics': lyrics, 'title': row[3]})
    else:
        return jsonify({'lyrics': [], 'title': []})



@app.route('/song/<id>')
def song(id):
    try:
        # Connect to the SQLite database
        conn=create_connection()
        cursor = conn.cursor()

        # Execute a query to select data from the 'songs' table for the selected ID
        cursor.execute(
            'SELECT lyrics, transliteration, chord, title, youtube_link FROM songs WHERE id = ?', (int(id),))

        row = cursor.fetchone()
        # print(row)

        # Close the database connection
        conn.close()

        lyrics = song_view(sanitize_html(row[0]), sanitize_html(row[1]), row[2])
    except:
        conn.close()
        return "Song Not Available!"

    # print("HI")

    return render_template("song_viewer.html", lyrics=lyrics, song_title=row[3], link=row[4])


@app.route('/control/<user>')
def control(user):
    if 'username' not in session:
        return render_template('login.html', error_message="Kindly Login to access controls Page!", error_color='red')
    login = True
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('logs.db')
        cursor = conn.cursor()

        # Define the current user
        current_user = session['username']

        # Execute the SQL query
        cursor.execute('''
            SELECT * FROM controls
            WHERE user = ? 
            AND time >= datetime('now', '-5 hours')
            ORDER BY time DESC
            LIMIT 1
        ''', (current_user,))

        # Fetch the result
        result = cursor.fetchone()

        # Check if a row was found
        if result:
            data = result[3]
        else:
            print("No rows found for user ")
            data = ""

    except sqlite3.Error as e:
        print("Error accessing SQLite database:", e)
    print(user)
    return render_template("control.html", login=login, user=session['username'], data=data)


@app.route('/display/<user>')
def display(user):
    print(user)

    return render_template("display.html", user=user)


@socketio.on('join')
def handle_join(user):
    room = user
    join_room(room)
    insert_logs(user)


@socketio.on('send_data_event')
def send_data(data):
    room = data.get('user')
    emitted_data = data.get('data')
    if room and emitted_data:
        emit('update_data', emitted_data, room=room)
        insert_control(room, emitted_data)


@socketio.on('send_para')
def send_para(data):
    room = data.get('user')
    emitted_data = data.get('data')
    if room and emitted_data:
        emit('update_para', emitted_data, room=room)
        insert_details(room, emitted_data)

# Function to fetch data from the database


def fetch_data(table_name):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    data = cursor.fetchall()
    conn.close()
    return data

# Route to display all tables


@app.route('/adminpanel')
def admin_view():
    if 'username' in session:
        log_details_data = fetch_data('log_details')
        details_data = fetch_data('details')
        controls_data = fetch_data('controls')
        return render_template('admin_view.html', log_details_data=log_details_data, details_data=details_data, controls_data=controls_data)
    else:
        return "Not Authorized to view this page"


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = create_connection()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            error_message = "Username or email already exists!"
            conn.close()
            return render_template('signup.html', error_message=error_message, error_color='red')

        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Insert new user into the database
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        session['username'] = username
        return redirect(url_for('login'))
    return render_template('signup.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if 'username' in session:
#         return redirect(url_for('dashboard'))

#     if request.method == 'POST':
#         username_or_email = request.form['username_or_email']
#         password = request.form['password']

#         conn=create_connection()
#         cursor = conn.cursor()

#         # Check if the username or email exists in the database
#         cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?",
#                        (username_or_email, username_or_email))
#         user = cursor.fetchone()

#         if user:
#             # Assuming the password is stored in the fourth column (index 3)
#             stored_password = user[3]
#             hashed_password = hashlib.sha256(password.encode()).hexdigest()

#             if hashed_password == stored_password:
#                 # Authentication successful, set session and redirect to a dashboard or profile page
#                 # Assuming the username is stored in the second column (index 1)
#                 session['username'] = user[1]
#                 conn.close()
#                 # Replace 'dashboard' with your desired route
#                 return redirect(url_for('dashboard'))
#             else:
#                 error_message = "Incorrect password"
#                 conn.close()
#                 return render_template('login.html', error_message=error_message, error_color='red')
#         else:
#             error_message = "User not found"
#             conn.close()
#             return render_template('login.html', error_message=error_message, error_color='red')

#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        conn = create_connection()
        cursor = conn.cursor()

        # Vulnerable SQL query construction
        query = "SELECT * FROM users WHERE username = '{}' OR email = '{}'".format(username_or_email, username_or_email)
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            # Assuming the password is stored in the fourth column (index 3)
            stored_password = user[3]
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            if hashed_password == stored_password:
                # Authentication successful, set session and redirect to a dashboard or profile page
                # Assuming the username is stored in the second column (index 1)
                session['username'] = user[1]
                conn.close()
                # Replace 'dashboard' with your desired route
                return redirect(url_for('dashboard'))
            else:
                error_message = "Incorrect password"
                conn.close()
                return render_template('login.html', error_message=error_message, error_color='red')
        else:
            error_message = "User not found"
            conn.close()
            return render_template('login.html', error_message=error_message, error_color='red')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        conn=create_connection()
        user = session['username']
        print(user)
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]
        conn.close()

        if session['username'] == "samjose":
            return redirect('/admincontrol')
        
        user_name = request.args.get('name') or session['username']

        dashboard_html = '''<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <title>Dashboard</title>
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <link
                rel="stylesheet"
                href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css"
                />
                <style>
                /* Add custom styles if needed */
                .card {
                    margin-bottom: 20px;
                }
                </style>
            </head>
        ''' + f'''
            <body>
                <br />
                <center>
                <h1>Welcome {user_name}!</h1>
                </center>
                <div class="container mt-4">
                <div class="row mt-4">
                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">All Songs / Home Page</h5>
                            <p class="card-text">Navigate to the All Songs.</p>
                            <a target="_blank" href="/" class="btn btn-primary"
                            >All Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Hindi Songs</h5>
                            <p class="card-text">Navigate to the Hindi Songs.</p>
                            <a target="_blank" href="/hindi" class="btn btn-primary"
                            >Hindi Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Telugu Songs</h5>
                            <p class="card-text">Navigate to the Telugu Songs.</p>
                            <a target="_blank" href="/telugu" class="btn btn-primary"
                            >Telugu Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>

                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Tamil Songs</h5>
                            <p class="card-text">Navigate to the Tamil Songs.</p>
                            <a target="_blank" href="/tamil" class="btn btn-primary"
                            >Tamil Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Malayalam Songs</h5>
                            <p class="card-text">Navigate to the Malayalam Songs.</p>
                            <a target="_blank" href="/malayalam" class="btn btn-primary"
                            >Malayalam Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>

                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Bible Page</h5>
                            <p class="card-text">Navigate to the Bible Page.</p>
                            <a target="_blank" href="/bible" class="btn btn-primary"
                            >Bible Page</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                    <div class="col-md-6">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Updates Page</h5>
                            <p class="card-text">Navigate to the Updates Page.</p>
                            <a target="_blank" href="/updates" class="btn btn-primary"
                            >Updates</a
                            >
                        </div>
                        </center>
                    </div>
                    </div> ''' + '''

                    <!-- Add more cards as needed -->

                    <div class="col-md-6">
                    <center>
                        <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Controls Page</h5>
                            <p class="card-text">Access controls page.</p>
                            <a
                            target="_blank"
                            href="/control/{{user_name}}"
                            class="btn btn-primary"
                            >Controls Page</a
                            >
                        </div>
                        </div>
                    </center>
                    </div>
                </div>
                <div class="row mt-4">
                    <div class="col">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Display Page</h5>
                            <p class="card-text">Go to the display page.</p>
                            <a
                            target="_blank"
                            href="/display/{{user_name}}_display"
                            class="btn btn-primary"
                            >Display Page</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                </div>

                {% if permission > 0 %}
                <div class="row mt-4">
                    <div class="col">
                    <div class="card">
                        <center>
                        <div class="card-body">
                            <h5 class="card-title">Add Songs</h5>
                            <p class="card-text">Add new songs to the database.</p>
                            <a target="_blank" href="/add_songs" class="btn btn-primary"
                            >Add Songs</a
                            >
                        </div>
                        </center>
                    </div>
                    </div>
                </div>
                {% endif %}
                </div>

                <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
        '''

        return render_template_string(dashboard_html, user_name=user_name, permission=permission )
        # return render_template("dashboard.html", user_name=user_name, permission=permission)
    return render_template('login.html', error_message="Kindly Login to access your dashboard!", error_color='red')


@app.route('/logout')
def logout():
    # Clear the user's session data
    # Replace 'username' with your session variable name
    session.pop('username', None)
    session.clear()
    

    # Redirect to the home page or login page after logout
    return redirect(url_for('home'))


@app.route('/add_songs', methods=['GET', 'POST'])
def add_songs():
    if 'username' not in session:
        return render_template('login.html', error_message="Kindly Login to add Songs!", error_color='red')
    
    else:
        conn = create_connection()
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

        if permission>0:


            if request.method == 'POST':
                transliteration_lyrics = request.form.get('transliterationLyrics')
                chord = request.form.get('chord')
                title = request.form['title']
                alternate_title = request.form.get('alternateTitle')
                lyrics = request.form['lyrics']
                youtube_link = request.form['youtube_link']
                search_title = remove_special_characters(
                    title) + " " + remove_special_characters(alternate_title)
                search_lyrics = lyrics.replace(
                    '\r\n', ' ') + " " + transliteration_lyrics.replace('\n', ' ')
                search_lyrics = remove_special_characters(search_lyrics)

                conn = create_connection()
                cursor = conn.cursor()

                # Get the current date and time
                current_date = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                # Insert song data into the songs table
                cursor.execute('''
                    INSERT INTO songs (title, alternate_title, lyrics, transliteration, youtube_link, chord, search_title, search_lyrics, create_date, modified_date, username)
                    VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (title, alternate_title, lyrics, transliteration_lyrics,
                    youtube_link, chord, search_title, search_lyrics, current_date, current_date, session['username']))

                cursor.execute('SELECT MAX(id) FROM songs')
                latest_id = cursor.fetchone()[0]

                conn.commit()
                conn.close()

                conn = sqlite3.connect('logs.db')
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO add_logs (user, time, link) VALUES (?, datetime('now'), ?)", (session['username'], f'/songs/{latest_id}'))
                conn.commit()
                conn.close()

                return redirect('/dashboard')

            return render_template('add_song.html')
        else:
            return jsonify({'message': 'Not authorized'}), 401


@app.route('/delete_song/<int:song_id>', methods=['DELETE'])
def delete_song(song_id):
    if 'username' not in session:
        # Unauthorized status code
        render_template('login.html', error_message="Kindly Login to delete Songs!", error_color='red')

    else:
        conn = create_connection()
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

        if permission>2:

            # Connect to the oilnwine database
            conn_oilnwine = create_connection()
            cur_oilnwine = conn_oilnwine.cursor()

            # Connect to the logs database
            conn_logs = sqlite3.connect('logs.db')
            cur_logs = conn_logs.cursor()

            # Get the row from the songs table in oilnwine database
            cur_oilnwine.execute("SELECT * FROM songs WHERE id=?", (song_id,))
            row_to_transfer = cur_oilnwine.fetchone()

            if row_to_transfer:
                # Get current time
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Update the modified_date column
                row_to_transfer = list(row_to_transfer)
                # Assuming modified_date is the last column
                row_to_transfer[-2] = current_time

                # Insert the row into the delete_logs table in logs database
                cur_logs.execute("""
                    INSERT INTO delete_logs (delete_id, title, alternate_title, lyrics, transliteration, chord, search_title, search_lyrics, youtube_link, create_date, modified_date, username)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, row_to_transfer)

                # Commit the transaction in logs database
                conn_logs.commit()
                print("Row transferred successfully.")
            else:
                print("No such row found in songs table in oilnwine database.")

            # Close connections
            conn_oilnwine.close()
            conn_logs.close()

            conn = create_connection()
            cursor = conn.cursor()

            # Delete the song based on the provided song_id
            cursor.execute('DELETE FROM songs WHERE id = ?', (song_id,))
            conn.commit()
            conn.close()

            # OK status code
            return jsonify({'message': 'Song deleted successfully'}), 200
        else:
            return jsonify({'message': 'Not authorized'}), 401


@app.route('/edit_songs/<int:id>', methods=['GET', 'POST'])
def edit_songs(id):
    if 'username' in session:
        conn = create_connection()
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute(
            'SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()
        permission = permission[0]

        if permission>1:
            try:
                conn=create_connection()
                cursor = conn.cursor()
                # Execute a query to select data from the 'songs' table for the selected ID
                cursor.execute('SELECT * FROM songs WHERE id = ?', (id,))
                default_values = cursor.fetchone()

                conn.close()

                if request.method == 'POST':
                    transliteration_lyrics = request.form.get(
                        'transliterationLyrics')
                    chord = request.form.get('chord')
                    title = request.form['title']
                    alternate_title = request.form.get('alternateTitle')
                    lyrics = request.form['lyrics']
                    youtube_link = request.form['youtube_link']
                    search_title = remove_special_characters(
                        title) + " " + remove_special_characters(alternate_title)
                    search_lyrics = lyrics.replace(
                        '\r\n', ' ') + " " + transliteration_lyrics.replace('\n', ' ')
                    search_lyrics = remove_special_characters(search_lyrics)

                    conn_oilnwine = sqlite3.connect('oilnwine.db')
                    cur_oilnwine = conn_oilnwine.cursor()

                    # Connect to the logs database
                    conn_logs = sqlite3.connect('logs.db')
                    cur_logs = conn_logs.cursor()

                    # Get the row from the songs table in oilnwine database
                    cur_oilnwine.execute("SELECT * FROM songs WHERE id=?", (id,))
                    row_to_transfer = cur_oilnwine.fetchone()

                    if row_to_transfer:
                        # Get current time
                        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        # Update the modified_date column
                        row_to_transfer = list(row_to_transfer)
                        # Assuming modified_date is the last column
                        row_to_transfer[-2] = current_time

                        # Insert the row into the delete_logs table in logs database
                        cur_logs.execute("""
                            INSERT INTO edit_logs (edit_id, title, alternate_title, lyrics, transliteration, chord, search_title, search_lyrics, youtube_link, create_date, modified_date, username)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, row_to_transfer)

                        # Commit the transaction in logs database
                        conn_logs.commit()
                        print("Row transferred successfully.")
                    else:
                        print("No such row found in songs table in oilnwine database.")

                    # Close connections
                    conn_oilnwine.close()
                    conn_logs.close()

                    conn = create_connection()
                    cursor = conn.cursor()

                    # Get the current date and time
                    current_date = str(
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                    cursor.execute('''
                                    UPDATE songs 
                                    SET title = ?, alternate_title = ?, lyrics = ?, 
                                        transliteration = ?, youtube_link = ?, chord = ?, search_title = ?, 
                                        search_lyrics = ?, modified_date = ?, username = ?
                                    WHERE id = ?
                                ''', (title, alternate_title, lyrics, transliteration_lyrics,
                                    youtube_link, chord, search_title, search_lyrics, current_date,
                                    session['username'], id))

                    print(title, alternate_title, lyrics, transliteration_lyrics,
                        youtube_link, chord, search_title, search_lyrics, current_date,
                        session['username'], id)

                    conn.commit()
                    conn.close()

                    return redirect(f'/song/{id}')
            except:
                conn.close()
                return "Selected Song Does not Exist."

            id = default_values[0]
            title = default_values[1]
            alternate_title = default_values[2]
            lyrics = default_values[3]
            transliteration_lyrics = default_values[4]
            chord = default_values[5]
            link = default_values[8]

            return render_template("edit_song.html", id=id, title=title, alternate_title=alternate_title, link=link, chord=chord, lyrics=lyrics, transliteration_lyrics=transliteration_lyrics)
        else:
            return jsonify({'message': 'Not authorized'}), 401
    return render_template('login.html', error_message="Kindly Login to edit Songs!", error_color='red')


@app.route('/admin_area')
def song_logs():
    # Connect to the SQLite database
    conn = sqlite3.connect('logs.db')
    cur = conn.cursor()

    # Fetch data from the add_logs table
    cur.execute("SELECT * FROM add_logs")
    add_logs = cur.fetchall()

    # Fetch data from the edit_logs table
    cur.execute("SELECT * FROM edit_logs")
    edit_logs = cur.fetchall()

    # Fetch data from the delete_logs table
    cur.execute("SELECT * FROM delete_logs")
    delete_logs = cur.fetchall()

    # Close the connection
    conn.close()

    # Render the HTML template and pass the data to it
    return render_template('song_logs.html', add_logs=add_logs, edit_logs=edit_logs, delete_logs=delete_logs)


@app.route('/updates')
def updates():
    return render_template('updates.html')

@app.route('/handle-url', methods=['POST'])
def handle_url():
    url = request.form.get('url')
    
    if url:
        # Check if the URL starts with 'https://'
        if url.startswith('https://'):
            # Check if the URL contains 'localhost'
            if 'localhost' in url:
                # Replace 'https' with 'http' if 'localhost' is in the URL
                url = url.replace('https://', 'http://', 1)
            
            # Perform the redirection
            return redirect(url)
        else:
            return "Not Allowed: URL must start with https://", 400
    else:
        return "No URL provided", 400

@app.route('/admin', methods=['GET', 'POST'])
def console():
    output = ''
    if request.method == 'POST':
        command = request.form['command']
        try:
            # Note: In a real-world application, never use shell=True with user input due to security risks
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            output = str(e)

    return render_template('console.html', output=output)

if __name__ == '__main__':
    socketio.run(app, 
                host='0.0.0.0', 
                port=5000,
                debug=True, 
                allow_unsafe_werkzeug=True,
                ssl_context='adhoc')
