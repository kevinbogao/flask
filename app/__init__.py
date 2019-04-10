import os
import sqlite3
import functools

from data import Articles
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash



### create database if it doesn't exesits ###

# path to database
DB_PATH = "database/app.sqlite"
# check if database exists
exists = os.path.isfile(DB_PATH)

if exists:
    pass
else:
    # create file
    os.mknod(DB_PATH)
    # change file permission
    os.chmod(DB_PATH, 0o644)
    # create connection
    conn = sqlite3.connect(DB_PATH)
    # create cursor
    cur = conn.cursor()
    # create users table
    cur.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100),
                    username VARCHAR(30),
                    password VARCHAR(100),
                    register_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
              """)
    # create posts table
    cur.execute("""
                CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(255),
                    author VARCHAR(100),
                    body TEXT,
                    create_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
              """)
    # commit change?
    conn.commit()
    # close connection
    conn.close()


# function for open database connection
def get_db():
    db = sqlite3.connect(DB_PATH)
    # return rows as dictionary
    db.row_factory = sqlite3.Row

    return db


# function for close database connection
def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()


# create and configure the app
app = Flask(__name__)
app.secret_key='dev'


# placeholder articles
Articles = Articles()

### login wrap ###
def logged_in(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'logged_in' in session:
            return view(**kwargs)
        else:
            flash('Unauthorised, Please login', 'error')
            return redirect(url_for('login'))
    return wrapped_view


########################### templates ##################################

### home page ###
@app.route('/')
def home():
    return render_template('home.html', active='home')





@app.route('/posts')
def posts():
    return render_template('posts.html', posts = Articles, active='posts')


@app.route('/post/<string:id>')
def post(id):
    return render_template('post.html', id=id)




### about page ###
@app.route('/about')
#@logged_in
def about():
    return render_template('home.html', active='about')

### registration ###
@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        input_pass = request.form['input_pass']
        confirm_pass = request.form['confirm_pass']

        # init database
        db = get_db()

        # reset error message
        error = None

        # error message
        if not name:
            error = 'Name is required'
        elif not username:
            error = 'Username is required'
        elif not input_pass:
            error = 'Please enter a password'
        elif not confirm_pass:
            error = 'Please confirm your passwd'
        elif input_pass != confirm_pass:
            error = 'The passwords entered are not the same'
        elif len(input_pass) < 7:
            error = 'The password will be more than 7 characters'
        elif db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'Username {} is already taken.'.format(username)

        # if no error has occurred
        if error is None:
            password = input_pass
            # inscert form into users table
            db.execute(
                'INSERT INTO users (name, username, password) VALUES(?, ?, ?)',
                (name, username, generate_password_hash(password))
            )
            db.commit()
            flash('You have successfully registered', 'success')
            return redirect(url_for('login'))

        flash(error, 'error')

    return render_template('register.html', active='register')


### user login ###
@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Username not found'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = username
            session['logged_in'] = True
            # flask message when logged in
            flash('You have logged in', 'success')
            return redirect(url_for('editor'))

        flash(error, 'error')

    return render_template('login.html', active='login')


### editor ###
@app.route('/editor')
def editor():
    return render_template('editor.html', active='editor')



### logout ###
@app.route('/logout')
@logged_in
def logout():
    session.clear()
    flash('You are now logged out')
    return redirect(url_for('login'))


if (__name__) == '__main__':
    app.run(debug=True)
