from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()  # Cargar las variables del archivo .env

# Obtener la ruta del archivo de credenciales desde una variable de entorno
credentials_path = os.getenv('GOOGLE_SHEETS_CREDENTIALS_PATH')

# Autenticación y acceso a Google Sheets
creds = ServiceAccountCredentials.from_json_keyfile_name(credentials_path, scope)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)

# Usuarios de prueba (puedes añadir un sistema real de autenticación)
users = {'admin': {'password': '1234'}}

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
    client = gspread.authorize(creds)

    # Abrir la hoja de cálculo por ID (reemplaza "your_spreadsheet_id" por tu ID real)
    sheet = client.open_by_key('1Xii15O4NZsAkAm9BCw796KV8cfD9jNtZ1pcDKS7A2yY').sheet1

    # Obtener la fecha y hora actual
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insertar el comentario y la fecha en la siguiente fila disponible
    sheet.append_row([comment, timestamp])

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
