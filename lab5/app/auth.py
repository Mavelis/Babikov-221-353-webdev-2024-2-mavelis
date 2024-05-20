from flask import Blueprint, request, url_for, render_template, flash, redirect, current_app
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from app import mysql
from checkRole import CheckRole
from functools import wraps

bp = Blueprint('auth', __name__, url_prefix = '/auth')



def init_login_manager(app):
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей'
    login_manager.login_message_category = 'warning'
    login_manager.user_loader(load_user)



def check_permission(action):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = kwargs.get('user_id')
            user = load_user(user_id)
            if not current_user.can(action, user):
                flash('Недостаточно прав доступа', 'danger')
                return redirect(url_for('index'))
            return func(*args, **kwargs)
        return wrapper
    return decorator
                


class User(UserMixin):
    def __init__(self,user_id,login, role_id):
        self.id = user_id
        self.login = login
        self.role_id = role_id
    
    def is_admin(self):
        return self.role_id == current_app.config['ADMIN_ROLE_ID']
    
    def can(self, action, record=None):
        check_role = CheckRole(record=record)
        method = getattr(check_role, action, None)
        if method:
            return method()
        return False
        

def load_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id=%s',(user_id,))
    user = cursor.fetchone()
    if user:
        return User(user_id=user.id,login=user.login, role_id=user.role_id)
    return None

@bp.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember')
        if login and password:
            cursor = mysql.connection().cursor(named_tuple=True)
            cursor.execute('SELECT * FROM users WHERE login=%s AND password_hash = SHA2(%s, 256)',(login,password))
            user = cursor.fetchone()
            if user:
                login_user(User(user_id=user.id,login=user.login, role_id=user.role_id),remember=remember)
                flash('Вы успешно прошли аутентификацию', 'success')
                next = request.args.get('next')
                return redirect(next or url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
