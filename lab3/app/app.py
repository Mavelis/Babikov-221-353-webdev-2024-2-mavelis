from flask import Flask, render_template, redirect, url_for, request, make_response, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)

app.config.from_pyfile('config.py')

login_manager = LoginManager();

login_manager.init_app(app);

login_manager.login_view = 'login'
login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей '
login_manager.login_message_category = 'warning'


def get_users():
    return [{"id":1, "login":"user","password":"123"}]

class User(UserMixin):
    def __init__(self,user_id,user_login):
        self.id = user_id
        self.login = user_login
        

@login_manager.user_loader
def load_user(user_id):
    for user in get_users():
        if user['id']==int(user_id):
            return User(user['id'],user['login'])
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember')
        for user in get_users():
            if user['login']==login and user['password']==password:
                login_user(User(user['id'],user['login']),remember=remember)
                flash('Вы успешно прошли аутентификацию', 'success')
                return redirect(url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/visits')
def visits():
    if 'visits' in session:
        session['visits'] += 1
    else:
        session['visits'] = 1
        
    return render_template('visits.html')

@app.route('/secret_page')
@login_required
def secret():
    return render_template('secret_page.html')

@app.context_processor
def inject_footer():
    return dict(footer_text='Бабиков Матвей Михайлович, 221-353')

