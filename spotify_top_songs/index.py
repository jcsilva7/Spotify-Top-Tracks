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
app.secret_key = os.getenv("FLASK_SECRET_KEY" ,os.urandom(24))

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

    if response.status_code != 200:
        return flask.jsonify({'error': 'Error'})

    return response.json()

def get_tracks(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get("https://api.spotify.com/v1/me/top/tracks?limit=15&time_range=short_term", headers=headers)

    if response.status_code != 200:
        return flask.jsonify({'error': 'Error'})
    else:
        return response.json()['items']

def make_playlist(name: str, description: str, is_public: str,  tracks: list, access_token) -> int:
    is_public = True if is_public == "1" else False

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    user_id = session.get('user_id')

    # Fetch playlists to check for duplicates
    playlists_resp = requests.get(
        f"https://api.spotify.com/v1/me/playlists?limit=50",
        headers=headers
    )

    if playlists_resp.status_code != 200:
        return -1

    playlists = playlists_resp.json()['items']
    playlist_id = None

    for pl in playlists:
        if pl['name'] == name:
            playlist_id = pl['id']
            break

    exist_previously = True

    # Create playlist if it doesn't exist
    if not playlist_id:
        exist_previously = False

        body = {
            'name': name,
            'description': description,
            'public': is_public
        }
        create_resp = requests.post(
            f"https://api.spotify.com/v1/users/{user_id}/playlists",
            headers=headers,
            json=body
        )
        if create_resp.status_code != 201:
            return -1
        playlist_id = create_resp.json()['id']

    # Add or replace tracks
    if tracks:

        uris = [t['uri'] for t in tracks]

        add_body = {'uris': uris}

        add_resp = requests.post(
            f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
            headers=headers,
            json=add_body
        )

        if add_resp.status_code not in (200, 201):
            if not exist_previously:
                 # Tries to delete (unfollow) playlist in case of error
                 requests.delete(
                    f"https://api.spotify.com/v1/playlists/{playlist_id}/followers",
                    headers=headers
                )

            return -1

    return playlist_id

def fetch_playlist(access_token, playlist_id):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    user_id = session.get('user_id')

    response = requests.get(
        f"https://api.spotify.com/v1/playlists/{playlist_id}",
        headers=headers
    )

    if response.status_code != 200:
        logger.error(f"Error fetching playlist data: {response.status_code}")
        return -1

    playlist = response.json()

    name = playlist['name']
    track_number = playlist['tracks']['total']

    p_time = sum(item['track']['duration_ms'] for item in playlist['tracks']['items']) / 1000 / 60
    p_time = round(p_time)

    return name, track_number, p_time

@app.route('/')
def home():
    return render_template('auth.html')

@app.route('/create')
def create():
    if session.get('access_token') is None:
        return redirect('/')

    try:
        error = session.pop('error')
    except KeyError:
        error = False

    user_info = get_user_info(session.get('access_token'))

    # User id for tracks request
    session['user_id'] = user_info['id']

    tracks = get_tracks(session.get('access_token'))
    current = time.localtime(time.time())
    month = calendar.month_name[current.tm_mon]
    year = current.tm_year

    return render_template('create.html', user=user_info, tracks=tracks, month=month, year=year, error=error, csrf_token=generate_csrf_token())

@app.route('/success')
def success():
    if 'access_token' not in session or not session.get('created'):
        return redirect('/')

    access_token = session.get('access_token')
    playlist_id = session.get('playlist_id')

    name, count, p_time = fetch_playlist(access_token, playlist_id)

    return render_template('success.html', name=name, count=count, time=p_time, id=playlist_id)

@app.route('/login')
def login_spotify():
    auth_url = (
        f'https://accounts.spotify.com/authorize'
        f'?response_type=code&client_id={CLIENT_ID}'
        f'&scope={SCOPE}'
        f'&redirect_uri={REDIRECT_URI}'
    )

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
        'client_secret': CLIENT_SECRET,
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

    if request.method == 'POST':
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
            logger.error(f"Failed to create playlist")
            session['error'] = True
            return redirect('/create')
        else:
            session['playlist_id'] = playlist_id
            session['created'] = True
            return redirect('/success')

    return redirect('/')

if __name__ == '__main__':
    # set up logging
    logging.basicConfig(filename='log_file.log')
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s', '%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # set up API
    host = os.getenv('API_HOST')
    port = os.getenv('API_PORT')
    app.run(host=host, port=port, threaded=True)
    logger.info(f'API stubs online: https://{host}:{port}')
