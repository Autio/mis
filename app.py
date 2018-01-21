from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, DateField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD']='1555'
app.config['MYSQL_DB']='misflaskapp'
app.config['MYSQL_CURSORCLASS']='DictCursor'
#init MYSQL
mysql = MySQL(app)

Articles = Articles()

# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

# Articles
@app.route ('/articles')
def articles():
    return render_template('articles.html', articles = Articles)

# Single article
@app.route ('/article/<string:id>/')
def article(id):
    return render_template('article.html', id=id)

# Register form class
class RegisterForm(Form):
    name = StringField(u'Name', validators=[validators.Length(min=1, max=50)])
    username = StringField(u'Name', validators = [validators.Length(min=4, max= 25)])
    email = StringField(u'Email', validators = [validators.Length(min=6, max= 50)])
    password = PasswordField(u'Password', validators = [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class ProjectForm(Form):
    projectName = StringField(u'Project Name', validators=[validators.Length(min=5, max=140)])
    projectStartDate = DateField(u'Start date YYYY-MM-DD', validators=[validators.InputRequired()])
    projectEndDate = DateField(u'End date YYYY-MM-DD', validators=[validators.InputRequired()])
    projectCode = StringField(u'Project code', validators=[validators.Length(min=3, max=5)])
    projectDescription = StringField(u'Project description', validators=[validators.Length(min=0, max=2000)])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():

        # What the user does in the form
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()
        cur.close()

        flash('You are now registered and can log in', 'success')

        redirect(url_for('index'))

    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form fields - not using wtforms since not needed
        username = request.form['username']
        # compare this against the real password
        password_candidate = request.form['password']

        # db connection
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users where username = %s", [username])

        if(result>0):
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.info('PASSWORD NOT MATCHED')
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            app.logger.info('NO USER FOUND')
            return render_template('login.html', error=error)

    return render_template('login.html')

# Add decorator to prevent access from those who are not logged in
# Check if the user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorised. Please log in.', 'danger')
            return redirect(url_for('login'))
        return wrapped
    return wrap

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard

@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')

@app.route('/project', methods=['GET', 'POST'])
def project():
    form = ProjectForm(request.form)
    if request.method == 'POST' and form.validate():

        # What the user does in the form
        projectName = form.projectName.data
        projectStartDate = form.projectStartDate.data
        projectEndDate = form.projectEndDate.data
        projectCode = form.projectCode.data

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO projects(projectName, projectStartDate, projectEndDate, projectCode) VALUES(%s, %s, %s, %s)", (projectName, projectStartDate, projectEndDate, projectCode))

        # Commit to DB
        mysql.connection.commit()
        cur.close()

        flash('Project information has been stored', 'success')

        redirect(url_for('index'))

    return render_template('project.html', form=form)

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug = True)
