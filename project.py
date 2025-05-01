from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import random
import re
import string
from flask_wtf.csrf import CSRFProtect, generate_csrf
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
csrf = CSRFProtect(app)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        upgraded_until DATETIME
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS upgrade_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        one_time_code TEXT,
        code_used INTEGER DEFAULT 0,
        privilege_hours INTEGER DEFAULT 1,
        privilege_minutes INTEGER DEFAULT 0,
        code_viewed INTEGER DEFAULT 0,
        code_attempts INTEGER DEFAULT 0
    )''')
    admin_username = "admin"
    admin_password = "admin1234567890!"
    salt = os.urandom(32)
    password_hash = hash_password(admin_password, salt)
    try:
        conn.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                     (admin_username, password_hash, salt.hex(), 'admin'))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

init_db()

def check_role_expiration():
    if 'user' in session and 'role' in session and session['role'] == 'upgraded_privilege_user':
        conn = sqlite3.connect('users.db')
        cursor = conn.execute("SELECT upgraded_until FROM users WHERE username=?", (session['user'],))
        result = cursor.fetchone()
        conn.close()
        if result and result[0]:
            upgraded_until = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
            if upgraded_until < datetime.now():
                conn = sqlite3.connect('users.db')
                conn.execute("UPDATE users SET role='user', upgraded_until=NULL WHERE username=?", (session['user'],))
                conn.commit()
                conn.close()
                session['role'] = 'user'
                return True
    return False

def require_role(roles):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if check_role_expiration():
                return redirect('/dashboard')
            if 'user' not in session or session.get('role') not in roles:
                return render_template_string('''
                    <h2>Доступ запрещён</h2>
                    У вас нет прав для доступа к этой странице.<br>
                    <a href="/dashboard">Назад в личный кабинет</a>
                ''')
            return func(*args, **kwargs)
        return wrapper
    return decorator

MAX_LOGIN_ATTEMPTS = 5

def is_valid_username(username):
    return re.match(r'^[\wа-яА-ЯёЁ]{3,32}$', username)

def is_valid_password(password):
    return len(password) >= 15 and re.search(r'[^\wа-яА-ЯёЁ]', password)

def has_pending_upgrade_request(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(
        "SELECT id, one_time_code, code_used FROM upgrade_requests WHERE username=? AND status='pending' ORDER BY id DESC LIMIT 1", (username,)
    )
    req = cursor.fetchone()
    conn.close()
    return req is not None and (not req[1] or req[2] == 0)

def generate_one_time_code(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def format_privilege_time(hours, minutes):
    if (hours is None and minutes is None) or (hours == 1 and minutes == 0):
        return ''
    parts = []
    if hours and hours > 0:
        parts.append(f"{hours} ч.")
    if minutes and minutes > 0:
        parts.append(f"{minutes} мин.")
    return ' '.join(parts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_valid_username(username):
            return render_template_string('''
                <h2>Ошибка</h2>
                Имя пользователя должно быть 3–32 символа, только буквы, цифры и подчёркивания.<br>
                <a href="/">Назад</a>
            ''')
        if not is_valid_password(password):
            return render_template_string('''
                <h2>Ошибка</h2>
                Пароль должен быть не короче 15 символов и содержать хотя бы 1 специальный символ.<br>
                <a href="/">Назад</a>
            ''')
        salt = os.urandom(32)
        password_hash = hash_password(password, salt)
        try:
            conn = sqlite3.connect('users.db')
            conn.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                         (username, password_hash, salt.hex(), 'user'))
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return render_template_string('''
                <h2>Ошибка</h2>
                Пользователь уже существует!<br>
                <a href="/">Назад</a>
            ''')
    return render_template_string('''
        <h2>Регистрация</h2>
        <form method="post">
            Имя: <input name="username" required>
            <small style="color:gray;">
                3–32 символа, только буквы (латиница/кириллица), цифры и подчёркивания.
            </small><br>
            Пароль: <input type="password" name="password" required>
            <small style="color:gray;">
                Минимум 15 символов, хотя бы 1 специальный символ (например, !@#$%^&*).
            </small><br>
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="submit" value="Зарегистрироваться">
        </form>
        <a href="/">Назад</a>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
    if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
        return render_template_string('''
            <h2>Аккаунт временно заблокирован</h2>
            Слишком много неудачных попыток входа. Попробуйте позже.<br>
            <a href="/">Назад</a>
        ''')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cursor = conn.execute("SELECT password_hash, salt, role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user:
            stored_hash, salt, role = user
            if stored_hash == hash_password(password, bytes.fromhex(salt)):
                session['user'] = username
                session['role'] = role
                session['login_attempts'] = 0
                return redirect('/dashboard')
        session['login_attempts'] += 1
        return render_template_string('''
            <h2>Ошибка</h2>
            Неверные данные!<br>
            <a href="/login">Попробовать снова</a><br>
            <a href="/">Назад</a>
        ''')
    return render_template_string('''
        <h2>Вход</h2>
        <form method="post">
            Имя: <input name="username" required>
            <br>
            Пароль: <input type="password" name="password" required>
            <br>
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="submit" value="Войти">
        </form>
        <a href="/">Назад</a>
    ''')

@app.route('/dashboard')
def dashboard():
    check_role_expiration()
    if 'user' not in session:
        return redirect('/login')
    time_info = ''
    if session.get('role') == 'upgraded_privilege_user':
        conn = sqlite3.connect('users.db')
        cursor = conn.execute("SELECT upgraded_until FROM users WHERE username=?", (session['user'],))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            upgraded_until = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
            time_info = f"<p style='color:green;'>Повышенные права действуют до: <b>{upgraded_until.strftime('%d.%m.%Y %H:%M')}</b></p>"
    links = '<a href="/user_area">Открытая информация</a><br>'
    links += '<a href="/special_area">Информация повышенного доступа</a><br>'
    if session['role'] == 'admin':
        links += '<a href="/confidential_area">Конфиденциальная информация</a><br>'
        links += '<a href="/admin">Панель администратора</a><br>'
    if session['role'] == 'user':
        links += '<a href="/request_upgrade">Запрос на повышение прав</a><br>'
        links += '<a href="/my_code">Мои коды</a><br>'
    return f'''<h2>Личный кабинет</h2>
              Добро пожаловать, {session['user']}!<br>
              Роль: {session['role']}<br>
              {time_info}
              {links}
              <a href="/logout">Выход</a>'''

@app.route('/my_code')
@require_role(['user'])
def my_code():
    username = session['user']
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(
        "SELECT id, one_time_code, code_used, code_viewed FROM upgrade_requests WHERE username=? AND status='pending' ORDER BY id DESC LIMIT 1",
        (username,))
    req = cursor.fetchone()
    code = None
    code_was_viewed = False
    if req and req[1] and not req[2]:
        if not req[3]:
            code = req[1]
            conn.execute("UPDATE upgrade_requests SET code_viewed=1 WHERE id=?", (req[0],))
            conn.commit()
        else:
            code_was_viewed = True
    conn.close()
    if code:
        return render_template_string('''
            <h2>Ваш одноразовый код</h2>
            <p style="font-size:2em; color:green;"><b>{{ code }}</b></p>
            <p>Скопируйте этот код и введите на странице подтверждения запроса.</p>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''', code=code)
    elif code_was_viewed:
        return render_template_string('''
            <h2>Код уже был просмотрен</h2>
            <p>Вы уже видели свой одноразовый код. Если вы его потеряли, запросите новый через форму повышения прав.</p>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''')
    else:
        return render_template_string('''
            <h2>Нет активного кода</h2>
            <p>У вас нет активного запроса или код ещё не был сгенерирован администратором.</p>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''')

@app.route('/user_area', endpoint='user_area')
@require_role(['user', 'upgraded_privilege_user', 'admin'])
def user_area():
    return '''
        <h2>Открытая информация</h2>
        Доступно для всех пользователей.<br>
        <a href="/dashboard">Назад в личный кабинет</a>
    '''

@app.route('/special_area', endpoint='special_area')
@require_role(['upgraded_privilege_user', 'admin'])
def special_area():
    return '''
        <h2>Информация повышенного доступа</h2>
        Доступно для пользователей с повышенными правами.<br>
        <a href="/dashboard">Назад в личный кабинет</a>
    '''

@app.route('/confidential_area', endpoint='confidential_area')
@require_role(['admin'])
def confidential_area():
    return '''
        <h2>Конфиденциальная информация</h2>
        Доступно только для администратора.<br>
        <a href="/dashboard">Назад в личный кабинет</a>
    '''

@app.route('/request_upgrade', methods=['GET', 'POST'], endpoint='request_upgrade')
@require_role(['user'])
def request_upgrade():
    username = session['user']
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(
        "SELECT id, status, one_time_code, code_used, privilege_hours, privilege_minutes, code_attempts FROM upgrade_requests WHERE username=? AND status='pending' ORDER BY id DESC LIMIT 1",
        (username,))
    req = cursor.fetchone()
    conn.close()

    if req and req[2] and not req[3]:
        if request.method == 'POST':
            if 'request_new_code' in request.form:
                conn = sqlite3.connect('users.db')
                conn.execute("UPDATE upgrade_requests SET status='denied' WHERE id=?", (req[0],))
                conn.commit()
                conn.close()
                return redirect('/request_upgrade')
            code = request.form.get('one_time_code', '')
            code_attempts = req[6] if req[6] is not None else 0
            if code_attempts >= 5:
                return render_template_string('''
                    <h2>Ошибка</h2>
                    Превышено максимальное количество попыток ввода кода.<br>
                    Запрос заблокирован. <a href="/request_upgrade">Запросить новый код</a><br>
                    <a href="/dashboard">Назад в личный кабинет</a>
                ''')
            if code == req[2]:
                duration_hours = req[4] if req[4] is not None else 1
                duration_minutes = req[5] if req[5] is not None else 0
                upgraded_until = datetime.now() + timedelta(hours=duration_hours, minutes=duration_minutes)
                conn = sqlite3.connect('users.db')
                conn.execute("UPDATE users SET role='upgraded_privilege_user', upgraded_until=? WHERE username=?",
                             (upgraded_until.strftime('%Y-%m-%d %H:%M:%S'), username))
                conn.execute("UPDATE upgrade_requests SET code_used=1, status='approved', code_attempts=0 WHERE id=?", (req[0],))
                conn.commit()
                conn.close()
                session['role'] = 'upgraded_privilege_user'
                end_str = upgraded_until.strftime('%d.%m.%Y %H:%M')
                return render_template_string(f'''
                    <h2>Код принят!</h2>
                    Вам предоставлены повышенные привилегии.<br>
                    Повышенные права действуют до: <b>{end_str}</b><br>
                    <a href="/dashboard">В личный кабинет</a>
                ''')
            else:
                conn = sqlite3.connect('users.db')
                conn.execute("UPDATE upgrade_requests SET code_attempts=code_attempts+1 WHERE id=?", (req[0],))
                conn.commit()
                conn.close()
                attempts_left = 5 - (code_attempts + 1)
                return render_template_string(f'''
                    <h2>Ошибка</h2>
                    Неверный одноразовый код.<br>
                    Осталось попыток: {attempts_left if attempts_left > 0 else 0}<br>
                    <a href="/request_upgrade">Попробовать снова</a>
                ''')
        return render_template_string('''
            <h2>Подтверждение запроса</h2>
            <form method="post">
                Введите одноразовый код, который вы получили от администратора:<br>
                <input name="one_time_code" required><br>
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="submit" value="Подтвердить">
            </form>
            <form method="post" style="margin-top:10px;">
                <input type="hidden" name="request_new_code" value="1">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="submit" value="Запросить новый код">
            </form>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''')

    if req and not req[2]:
        return render_template_string('''
            <h2>Запрос на повышение прав</h2>
            <p style="color:orange;">Ваш запрос отправлен. Ожидайте, пока администратор сгенерирует для вас одноразовый код.</p>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''')

    if request.method == 'POST':
        reason = request.form['reason']
        if len(reason) > 500:
            return render_template_string('''
                <h2>Ошибка</h2>
                Причина слишком длинная.<br>
                <a href="/dashboard">Назад в личный кабинет</a>
            ''')
        conn = sqlite3.connect('users.db')
        conn.execute("INSERT INTO upgrade_requests (username, reason) VALUES (?, ?)", (username, reason))
        conn.commit()
        conn.close()
        return render_template_string('''
            <h2>Запрос на повышение прав</h2>
            <p style="color:green;">Ваш запрос отправлен. Ожидайте, пока администратор сгенерирует для вас одноразовый код.</p>
            <a href="/dashboard">Назад в личный кабинет</a>
        ''')
    return render_template_string('''
        <h2>Запрос на повышение прав</h2>
        <form method="post">
            Причина: <textarea name="reason" maxlength="500"></textarea><br>
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="submit" value="Отправить запрос">
        </form>
        <a href="/dashboard">Назад в личный кабинет</a>
    ''')

@app.route('/admin', methods=['GET', 'POST'], endpoint='admin_panel')
@require_role(['admin'])
def admin_panel():
    conn = sqlite3.connect('users.db')
    cursor = conn.execute("SELECT * FROM upgrade_requests WHERE status='pending'")
    requests = cursor.fetchall()
    error_message = ""
    if request.method == 'POST':
        action = request.form['action']
        request_id = int(request.form['request_id'])
        if action == 'generate_code':
            try:
                duration_hours = int(request.form.get('privilege_hours', 1))
                duration_minutes = int(request.form.get('privilege_minutes', 0))
                if duration_hours < 0 or duration_minutes < 0:
                    raise ValueError("Время не может быть отрицательным")
                if duration_hours == 0 and duration_minutes == 0:
                    raise ValueError("Время не может быть нулевым")
            except Exception:
                duration_hours = 1
                duration_minutes = 0
            code = generate_one_time_code()
            conn.execute("UPDATE upgrade_requests SET one_time_code=?, privilege_hours=?, privilege_minutes=?, code_viewed=0, code_attempts=0 WHERE id=?",
                         (code, duration_hours, duration_minutes, request_id))
            conn.commit()
            error_message = f"<p style='color:green;'>Код для пользователя: <b>{code}</b>. Время действия: {duration_hours} ч. {duration_minutes} мин.</p>"
        elif action == 'deny':
            conn.execute("UPDATE upgrade_requests SET status='denied' WHERE id=?", (request_id,))
            conn.commit()
    conn.close()
    csrf_token = generate_csrf()
    requests_html = ''
    for req in requests:
        code_info = f"<b>Код: {req[5]}</b>" if req[5] else ""
        code_button = ""
        if not req[5]:
            code_button = f'''
                <form method="post" style="display:inline;">
                    <input type="hidden" name="request_id" value="{req[0]}">
                    <input type="number" name="privilege_hours" placeholder="Часы" min="0" value="1" required>
                    <input type="number" name="privilege_minutes" placeholder="Минуты" min="0" max="59" value="0" required>
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <button type="submit" name="action" value="generate_code">Сгенерировать код</button>
                </form>
            '''
        deny_button = f'''
            <form method="post" style="display:inline;">
                <input type="hidden" name="request_id" value="{req[0]}">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <button type="submit" name="action" value="deny">Отклонить</button>
            </form>
        '''
        time_info = format_privilege_time(req[6], req[7])
        if time_info:
            time_info = f"<i>Время: {time_info}</i>"
        requests_html += f'''
            <li>Запрос от {req[1]}: {req[2]} {code_info} {time_info}
            {code_button}
            {deny_button}
            </li>
        '''
    return render_template_string('''
        <h2>Панель администратора</h2>
        {{ error_message|safe }}
        <ul>{{ requests_html|safe }}</ul>
        <a href="/dashboard">Назад в личный кабинет</a>
    ''', error_message=error_message, requests_html=Markup(requests_html))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    if 'user' in session:
        return redirect('/dashboard')
    return render_template_string('''
        <h1>Главная страница</h1>
        <a href="/login">Вход</a><br>
        <a href="/register">Регистрация</a><br>
    ''')

if __name__ == '__main__':
    app.run()
