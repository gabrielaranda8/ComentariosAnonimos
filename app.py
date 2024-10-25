from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import os
import json

# Obtener la ruta del archivo de credenciales desde una variable de entorno
sheet_path = os.environ.get('SHEET_PATH', "1Xii15O4NZsAkAm9BCw796KV8cfD9jNtZ1pcDKS7A2yY")
user_path = os.environ.get('USER', "test")
pass_path = os.environ.get('PASS', "1234")

credentials_path = {
  "type": "service_account",
  "project_id": "comentariosanonimos",
  "private_key_id": os.environ.get('PRIVATE_KEY_ID', "8b0b645a4703874d63f86bcc4b0377e18cc17764"),
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcDsJH2/ASzrqd\nVEYRs93UheqmBDTuZhbipOjTjMBjmR5DEy/gjBzWFpODhiOCBqE0sO2Ac2L1eech\n2t5/PboAIwsh8NiYRO6ctNk1irm3BkM0c4/ZWJhTbe3nCDGu5w3XSp/jXDjGWtoo\neyM9pFLmVdImgj1dRNdi27Mzm05o+mTFKkQZvn8h1wlZ3xg78mYZ1/WvHUe/fIMn\nmhSpgXhLP2lHlkaDYgJD0kNZcnkYndoJp5xjH7IVX4+rWFyixIqeSO2nSfyFtXCC\nxoeX2Omqi4HCF9WEw6EttURAlSSHc+4z1mmzM1HS8VFUxtupAnQ5Y1EKYRDelXVT\nVBBW+12XAgMBAAECggEACg/Ti/GM0ZGdq54u5F5N+7Fkty6HQSW47QUH8/fbwbAy\nKM34ZMhz5YPQIAdKi8wkobKUpZcK9tvUwLSNavPOZcrcoWQXev3ayqTIanDW14ui\nUqPuzuss6xgn4iD/nxDLrilkFLMx/+wEq96An61UIQDAi3YTQcu5/Wg/7iBh1lfQ\nuwXiO3i9jF2UBVMz/eZIKKXzhgX820VDwEN24lOVOEWKY/fVSLnfe9TVtDkfQBB0\nWoHNRAcROzIvt5cgSyjVDOdw2KK3TQADV+1YHlPV3kp8Tl/e0ZlkdUKDXh53zG5e\n9JxdkItAWEygWKdoIEIyT84gPWqsdnayQD1yKUIFbQKBgQDblGoFRBkuzVB1E9y3\nTGvLME6Y+d3JkBY3x8eF3ShkHrq0TuhzwhgS37vyd5EaZHA578kPYv+rk+Ovbnus\n08N8NtlaCauh1yjDtUBvThF8VemjoRZar5aCCM+fy99rqb9zT9dvEbaNaEnm52x/\noAvs2RPbdbkAbYe7FFmjO9HjtQKBgQC18SFY1Ya3ppRt/WpaU2ICLs7u3qgo9RRi\nADzA6hESPndHEgzlOs/YNHqNCg72H6SOznZjsTGMiHyEb3WrdaJhVHkxxFvOUxvB\nQPTPdIYyKYFEbzWxJgs4nFdaFJJ3iB56xUKcbWVT6HWi/wNfmXfIHFabBPSHe1+n\ntgPSoinjmwKBgFcwdHTI2JML9aG3lFG4Z6kT8nGt7dJGg3v8uQ4/hfVTemF0X7rv\nXC3KZ0/dCGIJdcKboyOX9NuFashTP4qdv6bIBMBKzLsDu20SwJYx0qGjX5WYtk6m\nIEZcB011X67ZhWrdTjcNOoal3YpxZFS9EV8nx0nCUgaId3fimcFGVI5tAoGBAK9E\nm6g1AjMWgLQ4RGTBIJATwXqw+XODLGB/9AavNUTK8iJ/y/ZjImgXndsSTnlg4ChF\n0hyVTLMhpDn8GXHTv1pdguajTwFCZGFVjr/uc3wNKZ7gNuvxRywAx9FaMgJ+GUaR\nkmqYo90h+XjMitZkQ9R9IBzzuBBvlCU+nQ4i85FzAoGAQXUKyKkHoHajZ0F8O/vK\njrwQ+X75AtaExPrnjqb+lfa/zgqJeJl+S97PqzDxLwQDuPMQXZ0XRq8Yhhwk/YuL\n8bTM64R9D8G8JxVLaw2p6e6g9BaZnLzTE/sIHY+Tg0Hcd/tVCL3SnEXLUNiQi20x\nvK14SP8OIP0KcKvduwAJ53Q=\n-----END PRIVATE KEY-----\n",
  "client_email": os.environ.get('CLIENT_EMAIL', "garanda@comentariosanonimos.iam.gserviceaccount.com"),
  "client_id": os.environ.get('CLIENT_ID', "113085254374067423578"),
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": os.environ.get('CERT_URL', "https://www.googleapis.com/robot/v1/metadata/x509/garanda%40comentariosanonimos.iam.gserviceaccount.com"),
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
        # Recibe datos del formulario
        fecha = request.form['fecha']
        sector = request.form['sector']
        denunciado = request.form['denunciado']
        telefono = request.form.get('telefono', '')  # Campo opcional
        email = request.form.get('email', '')        # Campo opcional
        detalle = request.form['detalle']

        # Inserta los datos en Google Sheets
        save_comment_to_sheet(fecha, sector, denunciado, telefono, email, detalle)

        return 'Denuncia enviada con éxito.'

    return render_template('comment.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def save_comment_to_sheet(fecha, sector, denunciado, telefono, email, detalle):
    # Autenticación y acceso a Google Sheets
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    creds = ServiceAccountCredentials.from_json_keyfile_dict(credentials_path, scope)
    client = gspread.authorize(creds)

    # Abre la hoja de cálculo por ID
    sheet = client.open_by_key(sheet_path).sheet1

    # Inserta la denuncia en la siguiente fila disponible
    sheet.append_row([fecha, sector, denunciado, telefono, email, detalle, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
