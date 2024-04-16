from flask import Flask, render_template, redirect, url_for, request, make_response, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from mysql_db import MySQL

login_manager = LoginManager();

app = Flask(__name__)

app.config.from_pyfile('config.py')

mysql = MySQL(app)

login_manager.init_app(app);
login_manager.login_view = 'login'
login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей '
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self,user_id,login):
        self.id = user_id
        self.login = login
        

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id=%s',(user_id,))
    user = cursor.fetchone()
    if user:
        return User(user_id=user.id,login=user.login)
    return None

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users/')
@login_required
def users():
    cursor = mysql.connection().cursor()
    cursor.execute('SELECT id, login, first_name, last_name FROM users')
    users = cursor.fetchall()
    return render_template('users/index.html', users=users)


@app.route('/login',methods=['GET','POST'])
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
                login_user(User(user_id=user.id,login=user.login),remember=remember)
                flash('Вы успешно прошли аутентификацию', 'success')
                next = request.args.get('next')
                return redirect(next or url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')


@app.route('/users/register', methods=['GET','POST'])
@login_required
def register():
    if request.method == "GET":
        return render_template('users/register.html')

    login = request.form.get('loginInput')
    password = request.form.get('passwordInput')
    first_name = request.form.get('firstNameInput')
    last_name = request.form.get('lastNameInput')
    middle_name = request.form.get('middleNameInput')
    cursor = mysql.connection().cursor(named_tuple=True)
    query = """INSERT INTO users 
               (login, password_hash, first_name, last_name, middle_name)
               VALUES (%s, SHA2(%s, 256), %s, %s, %s)"""
    cursor.execute(query, (login, password, first_name, last_name, middle_name))
    mysql.connection().commit()
    cursor.close()
    flash('Успешная регистрация', 'success')
    return redirect(url_for('users'))



@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return render_template('/users/view.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index'))

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if request.method == 'POST':
        login = request.form.get('login')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        try:
            with mysql.connection().cursor(named_tuple=True) as cursor:
                cursor.execute('UPDATE users SET login = %s, first_name = %s, last_name = %s WHERE id = %s', (login, first_name, last_name, user_id,))
                mysql.connection().commit()
                flash('Сведения о пользователи успешно сохранены', 'success')
                return redirect(url_for('view_user', user_id=user_id))
        except Exception as e:
             mysql.connection().rollback()
             flash('Ошбика', 'danger')
             return render_template('users/edit.html')
    else:
        cursor = mysql.connection().cursor(named_tuple=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if user:
            return render_template('users/edit.html', user=user)
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('index'))
    
    
@app.route('/users/<int:user_id>/delete', methods=['GET','POST'])
@login_required
def delete_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection().commit()
    flash('Пользователь успешно удалён', 'success')
    return redirect(url_for('users'))
   

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))