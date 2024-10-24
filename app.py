from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import os
import json

# Obtener la ruta del archivo de credenciales desde una variable de entorno
sheet_path = os.environ.get('SHEET_PATH')
user_path = os.environ.get('USER')
pass_path = os.environ.get('PASS')

credentials_path = {
  "type": "service_account",
  "project_id": "comentariosanonimos",
  "private_key_id": os.environ.get('PRIVATE_KEY_ID'),
  "private_key": os.environ.get('PRIVATE_KEY'),
  "client_email": os.environ.get('CLIENT_EMAIL'),
  "client_id": os.environ.get('CLIENT_ID'),
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": os.environ.get('CERT_URL'),
  "universe_domain": "googleapis.com"
}


app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)

# Usuarios de prueba (puedes añadir un sistema real de autenticación)
users = {user_path: {'password': pass_path}}

# Clase de usuario para el manejo del login
class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return

    user = User()
    user.id = username
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        if username in users and request.form['password'] == users[username]['password']:
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('comment'))

    return render_template('login.html')

@app.route('/comment', methods=['GET', 'POST'])
@login_required
def comment():
    if request.method == 'POST':
        comment = request.form['comment']
        save_comment_to_sheet(comment)
        return 'Comment submitted successfully!'

    return render_template('comment.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def save_comment_to_sheet(comment):
    # Autenticación y acceso a Google Sheets
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    # Autenticación y acceso a Google Sheets
    creds = ServiceAccountCredentials.from_json_keyfile_dict(credentials_path, scope)

    client = gspread.authorize(creds)

    # Abrir la hoja de cálculo por ID (reemplaza "your_spreadsheet_id" por tu ID real)
    sheet = client.open_by_key(sheet_path).sheet1

    # Obtener la fecha y hora actual
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insertar el comentario y la fecha en la siguiente fila disponible
    sheet.append_row([comment, timestamp])

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
