from flask import Flask, render_template, redirect, url_for, request, make_response, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL


app = Flask(__name__)

app.config.from_pyfile('config.py')

mysql = MySQL(app)

from auth import bp, check_permission, init_login_manager
from stats import stats_bp

app.register_blueprint(bp)
app.register_blueprint(stats_bp)
init_login_manager(app)


@app.before_request
def add_stat():
    path = request.path
    user_id = getattr(current_user, 'id', None)
    cursor = mysql.connection().cursor(named_tuple=True)
    query = """INSERT INTO stats 
               (path, user_id)
               VALUES (%s, %s)"""
    cursor.execute(query, (path, user_id))
    mysql.connection().commit()
    cursor.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users/')
@login_required
def users():
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT users.*, roles.name as role_name FROM users LEFT JOIN roles on users.role_id = roles.id ')
    users = cursor.fetchall()
    return render_template('users/index.html', users=users)


def load_roles():
    with mysql.connection().cursor(named_tuple=True) as cursor:
        cursor.execute('SELECT id, name FROM roles')
        roles = cursor.fetchall()
    return roles


@app.route('/users/register', methods=['GET','POST'])
@login_required
@check_permission('create')
def register():
    if request.method == "GET":
        roles = load_roles()
        return render_template('users/register.html' , roles=roles)
    login = request.form.get('loginInput')
    password = request.form.get('passwordInput')
    first_name = request.form.get('firstNameInput')
    last_name = request.form.get('lastNameInput')
    middle_name = request.form.get('middleNameInput')
    role_id = request.form.get('choice')
    cursor = mysql.connection().cursor(named_tuple=True)
    query = """INSERT INTO users 
               (login, password_hash, first_name, last_name, middle_name, role_id)
               VALUES (%s, SHA2(%s, 256), %s, %s, %s, %s)"""
    cursor.execute(query, (login, password, first_name, last_name, middle_name, role_id))
    mysql.connection().commit()
    cursor.close()
    flash('Успешная регистрация', 'success')
    return redirect(url_for('users'))



@app.route('/users/<int:user_id>')
@login_required
@check_permission('show')
def view_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT users.*, roles.name AS role_name FROM users LEFT JOIN roles ON users.role_id = roles.id WHERE users.id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return render_template('/users/view.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index'))

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_permission('edit')
def edit_user(user_id):
    if not current_user.is_admin():
        if current_user.id != user_id:
            return redirect(url_for('index'))
    if request.method == 'POST':
        login = request.form.get('login')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')

        if current_user.is_admin():
            role_id = request.form.get('role_id')
        else:
            cursor = mysql.connection().cursor(named_tuple=True)
            cursor.execute('SELECT role_id FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            role_id = user.role_id if user else None
        try:
            with mysql.connection().cursor(named_tuple=True) as cursor:
                cursor.execute('UPDATE users SET login = %s, first_name = %s, last_name = %s, role_id = %s WHERE id = %s', (login, first_name, last_name, role_id, user_id))
                mysql.connection().commit()
                flash('Сведения о пользователи успешно сохранены', 'success')
                return redirect(url_for('view_user', user_id=user_id))
        except Exception as e:
             mysql.connection().rollback()
             flash('Ошбика', 'danger')
             return render_template('users/edit.html')
    # не post запрос
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        roles = load_roles()
        return render_template('users/edit.html', user=user, roles=roles)
    flash('Пользователь не найден', 'danger')
    return redirect(url_for('index'))
    
    
@app.route('/users/<int:user_id>/delete', methods=['GET','POST'])
@login_required
@check_permission('delete')
def delete_user(user_id):
    cursor = mysql.connection().cursor(named_tuple=True)
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection().commit()
    flash('Пользователь успешно удалён', 'success')
    return redirect(url_for('users'))

@app.context_processor
def inject_footer():
    return dict(footer_text='Бабиков Матвей Михайлович, 221-353')