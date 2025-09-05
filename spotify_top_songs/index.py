import flask
import os
import logging
import requests
import time
import calendar
import secrets
from flask import render_template, redirect, request, session
from dotenv import load_dotenv

load_dotenv()

app = flask.Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
app.config['SESSION_TYPE'] = 'filesystem'

CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID')
CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET')
REDIRECT_URI = os.getenv('SPOTIFY_REDIRECT_URI')
SCOPE = "user-read-email user-top-read playlist-modify-public playlist-modify-private"

def generate_csrf_token():
    if "_csrf_token" not in session:
        session['_csrf_token'] = secrets.token_hex(16)
        
    return session['_csrf_token']

def validate_csrf(token):
    return token and token == session.get("_csrf_token")

def get_user_info(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get("https://api.spotify.com/v1/me", headers=headers)
    try:
        data = response.json()
    except ValueError:
        logger.error(f"Invalid JSON response: {response.text}")
        return None
    
    if response.status_code != 200:
        logger.error(f"Error fetching user info: {data}")
        return None
    return data

def get_tracks(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get("https://api.spotify.com/v1/me/top/tracks?limit=15&time_range=short_term", headers=headers)
    try:
        data = response.json()
    except ValueError:
        logger.error(f"Invalid JSON response: {response.text}")
        return []
    
    if response.status_code != 200:
        logger.error(f"Error fetching tracks: {data}")
        return []
    
    return data.get('items', [])
    
def make_playlist(name, description, is_public, tracks, access_token):
    is_public = True if is_public == "1" else False
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    user_id = session.get('user_id')

    playlists_resp = requests.get(f"https://api.spotify.com/v1/me/playlists?limit=50", headers=headers)
    if playlists_resp.status_code != 200: return -1

    playlists = playlists_resp.json()['items']
    playlist_id = None
    for pl in playlists:
        if pl['name'] == name:
            playlist_id = pl['id']
            break

    exist_previously = True
    if not playlist_id:
        exist_previously = False
        
        body = {
            'name': name,
            'description': description,
            'public': is_public
        }
        
        create_resp = requests.post(f"https://api.spotify.com/v1/users/{user_id}/playlists", headers=headers, json=body)
        
        if create_resp.status_code != 201: return -1
            
        playlist_id = create_resp.json()['id']

    if tracks:
        uris = [t['uri'] for t in tracks]
        
        add_resp = requests.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json={'uris': uris})
        
        if add_resp.status_code not in (200, 201):
            if not exist_previously:
                requests.delete(f"https://api.spotify.com/v1/playlists/{playlist_id}/followers", headers=headers)
            return -1

    return playlist_id

def fetch_playlist(access_token, playlist_id):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(f"https://api.spotify.com/v1/playlists/{playlist_id}", headers=headers)
    if response.status_code != 200:
        logger.error(f"Error fetching playlist data: {response.status_code}")
        
        return -1

    playlist = response.json()
    
    name = playlist['name']
    
    track_number = playlist['tracks']['total']
    
    p_time = round(sum(item['track']['duration_ms'] for item in playlist['tracks']['items']) / 1000 / 60)
    
    return name, track_number, p_time

@app.route('/')
def home():
    return render_template('auth.html')

@app.route('/create')
def create():
    if not session.get('access_token'):
        return redirect('/')
        
    try:
        error = session.pop('error', False)
        
        user_info = get_user_info(session.get('access_token'))
        if not user_info:
            return redirect('/')
        
        session['user_id'] = user_info['id']
        tracks = get_tracks(session.get('access_token'))
        
        current = time.localtime(time.time())
        
        month = calendar.month_name[current.tm_mon]
        
        year = current.tm_year
    except Exception as e:
        logger.error(e)
        return redirect('/')
    
    return render_template('create.html', user=user_info, tracks=tracks, month=month, year=year, error=error, csrf_token=generate_csrf_token())

@app.route('/success')
def success():
    if 'access_token' not in session or not session.get('created'):
        return redirect('/')
        
    try:
        access_token = session.get('access_token')
        
        playlist_id = session.get('playlist_id')
        
        name, count, p_time = fetch_playlist(access_token, playlist_id)
    except Exception as e:
        logger.error(e)
        return redirect('/')
    
    return render_template('success.html', name=name, count=count, time=p_time, id=playlist_id)

@app.route('/login')
def login_spotify():
    auth_url = f'https://accounts.spotify.com/authorize?response_type=code&client_id={CLIENT_ID}&scope={SCOPE}&redirect_uri={REDIRECT_URI}'
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    token_url = 'https://accounts.spotify.com/api/token'
    
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    response = requests.post(token_url, data=payload)
    
    token = response.json()
    
    session['access_token'] = token['access_token']
    
    return redirect('/create')

@app.route('/create_playlist', methods=['POST'])
def create_playlist():
    access_token = session.get('access_token')
    if not access_token:
        return redirect('/')
        
    if not validate_csrf(request.form.get('csrf_token')):
        return redirect('/')
        
    playlist_name = request.form.get('playlist_name')
    if not playlist_name:
        session['error'] = True
        return redirect('/create')
        
    description = request.form.get('description') or ""
    is_public = request.form.get('is_public') or "0"
    
    tracks = get_tracks(access_token)
    playlist_id = make_playlist(playlist_name, description, is_public, tracks, access_token)
    if playlist_id == -1:
        logger.error("Failed to create playlist")
        
        session['error'] = True
        
        return redirect('/create')
    
    session['playlist_id'] = playlist_id
    session['created'] = True
    return redirect('/success')

logging.basicConfig(filename='log_file.log')
logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s', '%H:%M:%S')
ch.setFormatter(formatter)
logger.addHandler(ch)

