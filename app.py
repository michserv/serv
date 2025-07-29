
from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'clave_secreta_weye_server'
bcrypt = Bcrypt(app)

def init_db():
    if not os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                correo TEXT NOT NULL UNIQUE,
                clave TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['usuario']
        clave = request.form['clave']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM usuarios WHERE correo=?", (correo,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], clave):
            session['usuario'] = user[1]
            return redirect('/panel')
        else:
            flash('Correo o contraseña incorrectos')
            return redirect('/login')

    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        clave = request.form['clave']
        clave2 = request.form['clave2']

        if clave != clave2:
            flash('Las contraseñas no coinciden.')
            return redirect('/registro')

        clave_hash = bcrypt.generate_password_hash(clave).decode('utf-8')

        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO usuarios (nombre, correo, clave) VALUES (?, ?, ?)", (nombre, correo, clave_hash))
            conn.commit()
            conn.close()
            flash('Registro exitoso. Ya puedes iniciar sesión.')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('El correo ya está registrado.')
            return redirect('/registro')

    return render_template('registro.html')

@app.route('/panel')
def panel():
    if 'usuario' not in session:
        return redirect('/login')
    return render_template('panel.html', usuario=session['usuario'])

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect('/')

@app.route('/admin')
def admin():
    if 'usuario' not in session or session['usuario'] != 'admin':
        flash('Acceso denegado. Solo para el administrador.')
        return redirect('/panel')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, nombre, correo FROM usuarios")
    usuarios = c.fetchall()
    conn.close()
    return render_template('admin.html', usuarios=usuarios)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
