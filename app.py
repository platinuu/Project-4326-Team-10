from flask import Flask, render_template, request, redirect, url_for, make_response, session, jsonify, flash
from flask_session import Session
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from functools import wraps
import re
import os
import uuid
import bcrypt
import json
import shutil
import pyclamd

app = Flask(__name__, static_folder='')
mysql = MySQL(app)

app.config["SESSION_PERMANENT"] = False     # session data deleted when expires
app.config["SESSION_TYPE"] = "filesystem"   # session data stored in server in flask_session as files
                                            # this is so that every user has a folder and they can put their playlists and stuff
Session(app) # for server side sessions

####### uncomment the following and set the credentials ####### 
#app.config['MYSQL_HOST'] = ''      
#app.config['MYSQL_USER'] = ''           
#app.config['MYSQL_PASSWORD'] = ''     
#app.config['MYSQL_DB'] = ''    

     
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 mb

ALLOWED_EXTENSIONS = {'mp3', 'png', 'jpg', 'jpeg'}
#app.config['UPLOAD_FOLDER'] = 'users' #fix this, use https://stackoverflow.com/questions/44926465/upload-image-in-flask
#app.config['UPLOAD_FOLDER'] = 'images'
#app.static_folder = 'static'

def scan_files(file_path):
    # connect to ClamAV service
    connect = pyclamd.ClamdUnixSocket() 

    # check if the service is running
    if not connect.ping():
        raise Exception("Service isn't running")
    
    # scan files
    result = connect.scan_file(file_path) 

    if result:
        return f"Virus detected: {result}"
    return None

@app.route('/')
def home():
    # Creates a list for every name inside the artists directory
    artist_names = [name for name in os.listdir('artists') if os.path.isdir(os.path.join('artists', name))]
    return render_template('index.html', artists=artist_names)

@app.route('/login', methods=['GET', 'POST'])
def login():
    verification = False # This sets the value to false every time /login is accessed so that it is not True from the previous session
    if 'username' in session:
        if 'role' in session and session['role'] == 'creator':
            return redirect(url_for('artist_page', name=session['name']))
        else:
            return redirect(url_for('user_page', username=session['username']))
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT name, uname, email, password, uuid, role FROM user_info WHERE email = %s", (email,))
            
            user = cursor.fetchone()
            cursor.close()

            verification = False
            if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                verification = True
            
            if verification:
                session['username'] = user[4] 
                session['uname'] = user[1]
                session['role'] = user[5]
                session['name'] = user[0]
                user = None # Could be redundant, just makes sure to clear the database's info 
                if session['role'] == 'creator':
                    return redirect(url_for('artist_page', name=session['name']))
                elif session['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_page', username=session['username']))
    except Exception as e:
        print('Error:', e)
    return render_template('login.html')

def auth_user(user_db_info, email, password):
    try:
        if user_db_info[2] == email:
            if user_db_info[3] == password:
                return True

    except:
        return False # Email or Password are incorrect
''' Backup
@app.route('/user/<username>/playlist_making', methods=['GET', 'POST'])
def playlist_creation(username):
    if 'username' not in session or session['username'] != username:
        return 'You are not authorized to edit this profile', 403
    query = request.args.get('q')
    if query:
        artist_dir = 'artists'
        try:
            # list directory names for artists
            artists = [name for name in os.listdir(artist_dir) if os.path.isdir(os.path.join(artist_dir, name))]
            print(artists)  
        except Exception as e:
            print('Error: ', e)
            return jsonify([]) # empty
        # filters queries and gets rid of case sensitivity
        filtered_artists = [artist for artist in artists if query.lower() in artist.lower()]
        return jsonify(filtered_artists)

    # render main playlist creation page if they try to send something other than an AJAX req
    return render_template('playlist_making.html')
'''
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure user roles are in the session
            if 'role' not in session or not any(role in session['role'] for role in roles):
                return redirect(url_for('unauthorized'))  # Redirect if unauthorized
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/user/<username>/playlist_making', methods=['GET', 'POST'])
@role_required('user', 'admin')
def playlist_creation(username):
    if 'username' not in session or session['username'] != username:
        return 'You are not authorized to edit this profile', 403
    query = request.args.get('q', '').strip().lower()
    if query:  # handle autocomplete if q is there
        artist_path = os.path.join('artists')
        suggestions = [
            artist for artist in os.listdir(artist_path)
            if query in artist.lower() and os.path.isdir(os.path.join(artist_path, artist))
        ]
        return jsonify(suggestions)  # Return JSON suggestions

    # render playlist creation page (no q)
    if request.method == 'GET':
        return render_template('playlist_making.html', username=username)

    # playlist creation 
    if request.method == 'POST':
        artist_name = request.form.get('artist')
        album_name = request.form.get('album')
        playlist_name = request.form.get('playlist_name', 'New Playlist') 
        sanitized_playlist_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', playlist_name)
        songs = request.form.get('songs')  # JSON string of selected songs

        if not artist_name or not songs:
            return "Artist and at least one song are required to create a playlist", 400

        # JSON string into a Python list
        songs_list = json.loads(songs)

        # create the user's playlist directory
        user_path = os.path.join('users', session['username'])
        playlist_path = os.path.join(user_path, sanitized_playlist_name)
        os.makedirs(playlist_path, exist_ok=True)

        # create references to the selected songs in the playlist
        for song in songs_list:
            song_path = os.path.join('artists', artist_name, album_name, song)
            if os.path.exists(song_path):
                song_copy_path = os.path.join(playlist_path, song)
                shutil.copy(song_path, song_copy_path)
                #with open(song_reference_path, 'w') as f:
                #    f.write(f"Referenced song: {song_path}")
            else:
                return f"Song {song} not found", 404

        return f"Playlist '{sanitized_playlist_name}' created successfully"

@app.route('/get_artists')
def get_artists():
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([]) # empty if no query
    artist_path = os.path.join('artists')
    suggestions = [
        artist for artist in os.listdir(artist_path)
        if query in artist.lower() and os.path.isdir(os.path.join(artist_path, artist))

    ]
    return jsonify(suggestions)
    
@app.route('/get_albums')
def get_albums():
    artist = request.args.get('artist', '').strip()
    query = request.args.get('q', '').lower()
    artist_path = os.path.join('artists', artist)
    if not os.path.exists(artist_path):
        return jsonify([])
    albums = [album for album in os.listdir(artist_path) if query in album.lower() and os.path.isdir(os.path.join(artist_path, album))]
    return jsonify(albums)

@app.route('/get_songs')
def get_songs():
    artist = request.args.get('artist', '').strip()
    album = request.args.get('album', '').strip()
    query = request.args.get('q', '').lower()
    album_path = os.path.join('artists', artist, album)

    if not os.path.exists(album_path):
        return jsonify([])
    
    songs = [song for song in os.listdir(album_path) if query in song.lower() and song.endswith('.mp3')]
    return jsonify(songs)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_music', methods=['GET', 'POST'])
@role_required('creator', 'admin')
def upload_music():
    name = session['name']

    if request.method == 'POST':
        selected_playlist = request.form.get('playlist')
        music_file = request.files.get('music_file')
        
        # checks the file extension
        if not music_file or not allowed_file(music_file.filename):
            return "Invalid file, only MP3 allowed"
        
        # create music folder path on the playlist
        playlist_path = os.path.join('artists', name, selected_playlist)
        os.makedirs(playlist_path, exist_ok=True)

        # save music file to playlist music directory
        file_path = os.path.join(playlist_path, music_file.filename)
        
        music_file.save(file_path)
        #if scan_files(file_path):
        #    flash('Virus detected, file not uploaded')
        #    os.remove(file_path)
        #    return render_template('user_page.html')
        flash('File uploaded')
    user_path = os.path.join('artists', name)
    playlists = [d for d in os.listdir(user_path) if os.path.isdir(os.path.join(user_path, d))]
    return render_template('upload_music.html', playlists=playlists)

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/unauthorized')
def unauthorized():
    return "403 forbidden"

@app.route('/create_playlist', methods=['POST'])
def create_playlist():
    name = session['name']
    playlist_name = request.form['new_playlist']

    sanitized_playlist_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', playlist_name)

    # Create the playlist directory
    user_path = os.path.join('artists', name)
    playlist_path = os.path.join(user_path, sanitized_playlist_name)

    if not os.path.exists(playlist_path):
        os.makedirs(playlist_path)

    return redirect(url_for('upload_music'))  # Redirect back to the upload page

def fetch_owner(role_check, param):
    cursor = mysql.connection.cursor()
    if role_check == 0:
        cursor.execute("SELECT * FROM user_info WHERE uuid= %s", (param,))
    else:
        cursor.execute("SELECT * FROM user_info WHERE name= %s", (param,))
    user = cursor.fetchone()
    cursor.close()
    values = [user[0], user[1], user[4]]
    user = None
    return values # name, username, UUID

@app.route('/artists/<name>')
def artist_page(name):
    is_creator = False
    is_owner = False

    if 'username' not in session:
        return redirect(url_for('login'))
    owner_page = fetch_owner(1, name)
    if owner_page[2] == session['username']:
        is_owner = True
        if 'admin' or 'creator' in session:
            is_creator = True

    username_display = owner_page[1]

    user_folder = os.path.join('artists', name)
    if os.path.exists(user_folder):
        user_files = os.listdir(user_folder)
        return render_template('user_page.html', username=session['username'], is_owner=is_owner, files=user_files, username_display=username_display, is_creator=is_creator, is_user=False)
    else:
        return "User folder does not exist", 404
    

@app.route('/user/<username>')
def user_page(username):
    is_owner = False
    if 'username' not in session:
        return redirect(url_for('login'))
    owner_page = fetch_owner(0, username)
    if owner_page[2] == session['username']:
        is_owner = True
    username_display = owner_page[1] 
    user_folder = os.path.join('users', username)
    if os.path.exists(user_folder):
        user_files = os.listdir(user_folder)
        return render_template('user_page.html', username=session['username'], is_owner=is_owner, files=user_files, username_display=username_display, is_creator=False, is_user=True)
    else:
        return "User folder does not exist", 404
    
@app.route('/artists/<name>/<playlist_name>')
@role_required('user', 'creator', 'admin')
def playlist_display(name, playlist_name):
    if session['role'] == 'creator':
        param = 0
    if param == 0:
        if os.path.exists('users', name, playlist_name) and os.path.isdir('users', name, playlist_name):
            files = [file for file in os.listdir('artists', name, playlist_name) if file.endswith('.mp3')]
        else:
            files = []
    else:
        if os.path.exists('artists', name, playlist_name) and os.path.isdir('artists', name, playlist_name):
            files = [file for file in os.listdir('artists', name, playlist_name) if file.endswith('.mp3')]
        else:
            files = []

    return render_template('playlist_display.html', files=files, name=name, playlist_name=playlist_name)

@app.route('/<role_type>/<username>/edit_profile', methods=['GET','POST'])
@role_required('user', 'creator', 'admin')
def edit_profile(role_type, username):

    if 'username' not in session or session['username'] != username:
        return 'You are not authorized to edit this profile', 403
    if role_type == 'user':
        role_type = 'users'
    else:
        role_type = 'artists'
        username = session['name']
    if request.method == 'POST':
        file = request.files.get('profile_picture')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_folder = os.path.join(role_type, username)  # Replace 'uuid' with the user's actual UUID
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)  # Create the folder if it doesn't exist
            file_path = os.path.join(user_folder, 'profile.png')
            file.save(file_path)
            flash('Profile picture updated successfully!', 'success')

    return render_template('edit_profile.html')

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    try:
        if request.method == 'POST':
            name = request.form['name']
            uname = request.form['uname']
            email = request.form['email']
            hashed_password = hashing_password(request.form['password'])
            role_type = request.form.get('role', 'user') # if for some reason none is selected, which shouldn't be possible, it will default to user
            user_uuid = str(uuid.uuid4())
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO user_info (name, uname, email, password, uuid, role) VALUES (%s, %s, %s, %s, %s, %s)", (name, uname, email, hashed_password, user_uuid, role_type))
            session['username'] = user_uuid
            session['uname'] = uname
            session['role'] = role_type
            session['name'] = name
            mysql.connection.commit()
            cursor.close()
            if role_type == 'creator':
                user_folder = os.path.join('artists', name)    
                if not os.path.exists(user_folder):
                    os.makedirs(user_folder)
                return redirect(url_for('artist_page', name=name))
            else:
                user_folder = os.path.join('users', user_uuid)
                if not os.path.exists(user_folder):
                    os.makedirs(user_folder)
                return redirect(url_for('user_page', username=user_uuid))

    except Exception as e:
        print('error: ', e)
        return 'Something went wrong'
        # What likely happened is that the username/email was repeated, I set a unique value index on the DB for username/email
    return render_template('add_user.html') 

@app.route('/<role_type>/<uuid>/<playlist_name>')
def display_playlist(role_type, uuid, playlist_name):
    if role_type == 'user':
        role_type = 'users'
    else:
        role_type = 'artists'
        uuid = session['name']
    playlist_path = os.path.join(role_type, uuid, playlist_name)
    if not os.path.exists(playlist_path) or not os.path.isdir(playlist_path):
        return "Playlist doesn't exist", 404
    songs = [song for song in os.listdir(playlist_path) if song.endswith('.mp3')]
    return render_template('playlist_page.html', role=role_type, username=uuid, playlist_name=playlist_name, songs=songs)

@app.route('/logout')
def logout():
    session.clear()
    return render_template('index.html')

def hashing_password(password): 
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt) # encoded from string to bytes 
    return hashed.decode('utf-8') # decoded so that it gets converted from bytes to string to put into the DB since it stores strings not bytes

if __name__ == '__main__':
    app.run(debug=True)

