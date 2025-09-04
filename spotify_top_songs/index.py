import flask
import os
import logging
import requests
import time
import calendar
from flask import render_template, redirect, request, session
from dotenv import load_dotenv
from oauthlib.oauth1.rfc5849.endpoints import access_token

load_dotenv()

app = flask.Flask(__name__)
app.secret_key = os.urandom(24)

CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID')
CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET')
REDIRECT_URI = os.getenv('SPOTIFY_REDIRECT_URI')
SCOPE = "user-read-email user-top-read playlist-modify-public playlist-modify-private"

def get_user_info(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get("https://api.spotify.com/v1/me", headers=headers)

    if response.status_code != 200:
        return flask.jsonify({'error': 'Error'})

    return response.json()

def get_tracks(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get("https://api.spotify.com/v1/me/top/tracks?limit=10&time_range=short_term", headers=headers)

    if response.status_code != 200:
        return flask.jsonify({'error': 'Error'})
    else:
        return response.json()['items']

def make_playlist(name: str, description: str, is_public: str,  tracks: list) -> int:
    if is_public == 1:
        is_public = True
    else: is_public = False

    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}

    body = {
        'name': name,
        'description': description,
        'public': is_public,
    }

    response = requests.post(
        f'https://api.spotify.com/v1/users/{session.get('user_id')}/playlists',
        headers=headers,
        data=body
    )

    if response.status_code != 200:
        return -1

    return response.json()['id']

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

    session['user_id'] = user_info['id']

    tracks = get_tracks(session.get('access_token'))
    current = time.localtime(time.time())
    month = calendar.month_name[current.tm_mon]
    year = current.tm_year

    return render_template('create.html', user=user_info, tracks=tracks, month=month, year=year, error=error)

@app.route('/success')
def success():
    if session.get('access_token') or session.get('created') is None:
        return redirect('/')

    return render_template('success.html')

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

    playlist_name = request.form.get('playlist_name')

    description = request.form.get('description')

    is_public = request.form.get('is_public')

    tracks = get_tracks(access_token)

    if make_playlist(playlist_name, description, is_public, tracks) == -1:
        session['error'] = True
        return redirect('/create')
    else:
        session['created'] = True
        return redirect('/success')

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
    app.run(host=host, port=port, debug=True, threaded=True)
    logger.info(f'API stubs online: https://{host}:{port}')
