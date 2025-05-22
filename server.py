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
secret_key="hello"
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
        conn = create_connection()
        user = session['username']
        cursor1 = conn.cursor()
        cursor1.execute('SELECT permission FROM users where username = ?', (user,))
        permission = cursor1.fetchone()[0]
        conn.close()

        if session['username'] == "samjose":
            return redirect('/admincontrol')
        
        user_name = request.args.get('name') or session['username']
        
        return render_template('dashboard.html', user_name=user_name, permission=permission)
        
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
        command = request.form['command'].strip()
        
        # Whitelist of allowed commands
        allowed_commands = ['ls', 'pwd', 'dir', 'clear', 'cls', 'help', 'exit', 'quit', 'more server.py', 'type']
        
        # Common dangerous commands to give false errors for
        dangerous_commands = ['rm', 'cat', 'sudo', 'su', 'chmod', 'chown', 'wget', 'curl', 'nc', 'netcat', 'bash', 'sh']
        
        # Check if command is in dangerous list
        for dangerous in dangerous_commands:
            if command.startswith(dangerous):
                output = f"Error: Command '{dangerous}' blocked by Cloudflare WAF"
                return render_template('console.html', output=output)
        
        # Check if command is in whitelist
        if command in allowed_commands:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                output = result.stdout if result.returncode == 0 else result.stderr
            except Exception as e:
                output = str(e)
        else:
            output = f"Error: Command '{command}' malicious activity detected"

    return render_template('console.html', output=output)

if __name__ == '__main__':
    socketio.run(app, 
                host='0.0.0.0', 
                port=5000,
                debug=True, 
                allow_unsafe_werkzeug=True,
                ssl_context='adhoc')
