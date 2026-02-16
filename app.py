from flask import Flask, request, render_template_string, redirect, url_for, session
import requests, os
from functools import wraps
from flask_talisman import Talisman

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecreto123") 

# 🔒 Headers de seguridad
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

Talisman(app, content_security_policy=None)

# 🔐 Credenciales Zoho
REFRESH_TOKEN = os.environ.get("1000.040d273c0553c4b984d3a20522f7b294.19f8d5833e8925d1bd2dadc8c42574f4")
CLIENT_ID = os.environ.get("1000.BECRQH6DSK7Q8HXA0AEMAT0PFUXLLX")
CLIENT_SECRET = os.environ.get("47f97dc641bd39ac0511af6a48f36f9da8ea2772c4")
WORKSPACE_OWNER = "juan.martinez@gse.com.co"
WORKSPACE_NAME = "All Company"
TABLE_NAME = "Export_Form_Automatico"

# 👥 Usuarios gratis
USUARIOS = {
    "juan": "1234",
    "maria": "abcd",
    "pablo": "pass123"
}

# 🔒 Login protegido
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        usuario = request.form.get("usuario")
        clave = request.form.get("clave")
        if usuario in USUARIOS and USUARIOS[usuario] == clave:
            session["usuario"] = usuario
            return redirect(url_for("home"))
        else:
            error = "Usuario o contraseña incorrectos"
    return render_template_string("""
    <h2>Login Portal Zoho</h2>
    <form method="POST">
        Usuario:<br>
        <input type="text" name="usuario" required><br>
        Contraseña:<br>
        <input type="password" name="clave" required><br>
        <button type="submit">Ingresar</button>
    </form>
    {% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
    """, error=error)

@app.route("/logout")
@login_required
def logout():
    session.pop("usuario", None)
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    data = []
    columns = []
    error_msg = None

    if request.method == "POST":
        contrato = request.form.get("contrato")
        fecha_ini = request.form.get("fecha_ini")
        fecha_fin = request.form.get("fecha_fin")

        try:
            access_token = get_access_token()
        except Exception as e:
            error_msg = f"Error al obtener access token: {e}"
            access_token = None

        if access_token:
            url = f"https://www.zohoapis.com/analytics/v2/{WORKSPACE_OWNER}/{WORKSPACE_NAME}/report/{TABLE_NAME}/data"
            headers = {"Authorization": f"Bearer {access_token}"}
            filters = {"criteria": f'("Contrato" == "{contrato}" && "Fecha" >= "{fecha_ini}" && "Fecha" <= "{fecha_fin}")'}
            try:
                resp = requests.post(url, headers=headers, json=filters, timeout=10)
                resp.raise_for_status()
                result = resp.json()
                data = result.get("result", {}).get("rows", [])
                columns = result.get("result", {}).get("columns", [])
            except Exception as e:
                error_msg = f"No se pudieron obtener los datos: {e}"

    return render_template_string("""
    <h2>Portal Zoho</h2>
    <p>Bienvenido, {{ session['usuario'] }} | <a href="{{ url_for('logout') }}">Cerrar sesión</a></p>
    <form method="POST">
        Contrato:<br><input type="text" name="contrato" required><br>
        Fecha Inicial:<br><input type="date" name="fecha_ini" required><br>
        Fecha Final:<br><input type="date" name="fecha_fin" required><br>
        <button type="submit">Ver Datos</button>
    </form>
    {% if error_msg %}<p style="color:red;">{{ error_msg }}</p>{% endif %}
    {% if data %}
        <table border="1" cellpadding="5">
            <thead><tr>{% for col in columns %}<th>{{ col.get('name') }}</th>{% endfor %}</tr></thead>
            <tbody>{% for row in data %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>{% endfor %}</tbody>
        </table>
    {% endif %}
    """, data=data, columns=columns, error_msg=error_msg)

def get_access_token():
    url = "https://accounts.zoho.com/oauth/v2/token"
    params = {
        "refresh_token": REFRESH_TOKEN,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token"
    }
    resp = requests.post(url, data=params, timeout=10)
    result = resp.json()
    if "access_token" not in result:
        raise Exception(f"No se pudo obtener access_token: {result}")
    return result["access_token"]

# Start
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)



