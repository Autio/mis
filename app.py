from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, DateField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import csv

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
language = 'English'
languageFile = {}
# Read in localisation
#try:
#    with open('localisation/English.csv', mode='r') as langfile:
#        reader = csv.reader(langfile)
#        with open('/localisation/tempfile.csv', mode'w') as outfile:
#            writer = csv.writer(outfile)
#        languageFile = {rows[0]:rows[1] for rows in reader}
#        app.logger.info(languageFile)
#except:
#   app.logger.info("Error loading language file")

# Index
@app.route('/')
def index():
    return render_template('home.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')


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
    projectDescription = StringField(u'Project description', validators=[validators.InputRequired()])

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
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM projects")

    projects = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html', projects=projects)
    else:
        msg = 'No projects found'
        return render_template('dashboard.html', msg=msg)

    # Close connection
    cur.close()


@app.route('/add_project', methods=['GET', 'POST'])
@is_logged_in
def project():
    form = ProjectForm(request.form)
    if request.method == 'POST' and form.validate():

        # What the user does in the form
        projectName = form.projectName.data
        projectStartDate = form.projectStartDate.data
        projectEndDate = form.projectEndDate.data
        projectCode = form.projectCode.data
        projectDescription = form.projectDescription.data

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO projects(projectName, projectStartDate, projectEndDate, projectCode, projectDescription) VALUES(%s, %s, %s, %s, %s)", (projectName, projectStartDate, projectEndDate, projectCode, projectDescription))

        # Commit to DB
        mysql.connection.commit()
        cur.close()

        flash('Project information has been stored', 'success')

        redirect(url_for('dashboard'))

    return render_template('add_project.html', form=form)

@app.route('/edit_project/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_project(id):
    # Get Form
    form = ProjectForm(request.form)

    # retrieve the project, then edit it
    cur = mysql.connection.cursor()

    # get project by ID
    result = cur.execute("SELECT * FROM projects WHERE id = %s", [id])

    project = cur.fetchone()

    # Populate project from fields
    form.projectName.data = project['projectName']
    form.projectStartDate.data = project['projectStartDate']
    form.projectEndDate.data = project['projectEndDate']
    form.projectCode.data = project['projectCode']
    form.projectDescription.data = project['projectDescription']

    if request.method == 'POST' and form.validate():

        # What the user does in the form
        projectName = form.projectName.data
        projectStartDate = form.projectStartDate.data
        projectEndDate = form.projectEndDate.data
        projectCode = form.projectCode.data
        projectDescription = form.projectDescription.data

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("UPDATE projects SET projectName=%s, projectStartDate=%s, projectEndDate=%s, projectCode=%s, projectDescription=%s WHERE id = %s", (projectName, projectStartDate, projectEndDate, projectCode, projectDescription, id))

        # Commit to DB
        mysql.connection.commit()
        cur.close()
        flash('Project information has been updated', 'success')

        redirect(url_for('dashboard'))

    return render_template('edit_project.html', form=form)


if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug = True)
