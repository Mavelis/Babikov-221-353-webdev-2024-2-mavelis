from flask import Flask, render_template, request

app = Flask(__name__)

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Страница с формой
@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        # Действия при отправке формы
        # Можно добавить обработку данных формы здесь
        pass
    return render_template('form.html')

# Страница с заголовками запроса
@app.route('/headers')
def headers():
    return render_template('headers.html')

# Страница с параметрами URL
@app.route('/args')
def args():
    return render_template('args.html')

# Страница с куки
@app.route('/cookie')
def cookie():
    return render_template('cookie.html')



@app.route('/phone_check', methods=['GET', 'POST'])
def phone_check():
    if request.method == 'POST':
        phone_number = request.form.get('phone_number', '')
        # Проверка длины номера и наличия только допустимых символов
        if not (10 <= len(phone_number) <= 11 and phone_number.replace('+', '').replace(' ', '').replace('-', '').replace('(', '').replace(')', '').replace('.', '').isdigit()):
            error_message = ""
            if len(phone_number) not in [10, 11]:
                error_message = "Недопустимый ввод. Неверное количество цифр."
            else:
                error_message = "Недопустимый ввод. В номере телефона встречаются недопустимые символы."
            return render_template('phone_form.html', error_message=error_message, phone_number=phone_number, is_invalid=True)
        
        # Преобразование номера к формату 8-***-***-**-**
        if phone_number[0] == '+':
            formatted_phone_number = '8-' + phone_number[2:5] + '-' + phone_number[6:9] + '-' + phone_number[10:12] + '-' + phone_number[12:]
        else:
            formatted_phone_number = '8-' + phone_number[1:4] + '-' + phone_number[4:7] + '-' + phone_number[7:9] + '-' + phone_number[9:]
        return render_template('phone_form.html', formatted_phone_number=formatted_phone_number)
    
    return render_template('phone_form.html')

@app.context_processor
def inject_footer():
    return dict(footer_text='Бабиков Матвей Михайлович, 221-353')

if __name__ == '__main__':
    app.run(debug=True)
