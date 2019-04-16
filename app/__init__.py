# -*- coding: utf-8 -*-
"""Flask backend

Note: The code severs as backend for a simple blog;
it handles registration, logins, and more

Notes on __init__.py
--------------------
It is a monolithic script, and it may need to be broken
up into moduals for scaling

XXX TODO:
- Change the the posts database stracture!
- Check for the folder first for creating the database
- Maybe change sqlite to MariaDB
- Change get_db() and close_db() into my own code
- Format post url

NOTE: recommeded flash messages are
1. message
2. error
3. info
4. warning

"""

import os
import sqlite3
import functools
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


# Create database if it doesn't exsist
DB_PATH = "database/app.sqlite"

if os.path.isfile(DB_PATH):
    pass
else:
    # create file
    os.mknod(DB_PATH)
    # change file permission
    os.chmod(DB_PATH, 0o644)
    # create connection
    CON = sqlite3.connect(DB_PATH)
    # create cursor
    CUR = CON.cursor()

    # create users table
    CUR.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100),
                    username VARCHAR(30),
                    password VARCHAR(100),
                    register_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
              """)

    # create posts table
    CUR.execute("""
                CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_id INTEGER,
                    title VARCHAR(255),
                    body TEXT,
                    create_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (author_id) REFERENCES users (id)
                );
              """)
    # commit change?
    CON.commit()
    # close connection
    CON.close()


# Create and configure the app
app = Flask(__name__)
app.secret_key = 'dev'


# database connection
def db_con():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# Login wrap
def logged_in(view):
    """Return a new function that warps the orginal view,
    the new function check if the user is logged in

    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'logged_in' in session:
            return view(**kwargs)
        else:
            flash('Please login to view this page', 'error')
            return redirect(url_for('login'))
    return wrapped_view


# Home page
@app.route('/')
def home():
    """Returns the home page template"""
    return render_template('home.html', active='home')


# About page
@app.route('/about')
def about():
    """Returns the about page template"""
    return render_template('about.html', active='about')


# Posts page
@app.route('/posts')
def all_posts():
    """Returns the posts template which displays all posts that were
    posted on the site.
    All the posts are extracted from the sqlite database, users and posts
    table
    """
    con = db_con()
    posts = con.execute(
                'select posts.title, posts.body, posts.create_date, users.name'
                ' from posts inner join users on posts.author_id=users.id'
                ' order by create_date desc'
    ).fetchall()
    con.close()
    return render_template('posts.html', posts=posts, active='posts')


# Single post page
@app.route('/post/<string:title>')
def single_post(title):
    """
    TODO: docstring, maybe redo the query
    Args:
        title (str): the title of the selected post

    Returns:
        The rendered template (full view) of the selected post

    """
    con = db_con()
    post = con.execute("SELECT * FROM posts WHERE title = ?", [title]).fetchone()
    con.close()
    return render_template('post.html', post=post, active='posts')


# Registration page
@app.route('/register', methods=('GET', 'POST'))
def register():
    """Returns the registration template
    The user is instructed to
    """
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        input_pass = request.form['input_pass']
        confirm_pass = request.form['confirm_pass']

        con = db_con()

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
        elif con.execute(
                'SELECT id FROM users WHERE username = ?', [username]
        ).fetchone() is not None:
            error = 'Username {} is already taken.'.format(username)

        # if no error has occurred
        if error is None:
            password = input_pass
            # inscert form into users table
            con.execute(
                'INSERT INTO users (name, username, password) VALUES (?, ?, ?)',
                [name, username, generate_password_hash(password)]
            )
            con.commit()
            con.close()
            flash('You have successfully registered', 'success')
            return redirect(url_for('login'))

        flash(error, 'error')

    return render_template('register.html', active='register')


# Login page
@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        con = db_con()

        error = None

        user = con.execute(
            'SELECT * FROM users WHERE username = ?', [username]
        ).fetchone()

        if user is None:
            error = 'Username not found'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['logged_in'] = True

            flash('You have logged in', 'success')
            return redirect(url_for('editor'))

        flash(error, 'error')

    return render_template('login.html', active='login')


# Editor page
@app.route('/editor')
def editor():
    con = db_con()

    error = None

    posts = con.execute(
                'SELECT posts.id, posts.title, posts.body, posts.create_date, users.name'
                ' FROM posts INNER JOIN users ON posts.author_id=users.id'
                ' WHERE author_id = ?'
                ' ORDER BY create_date DESC', [session['user_id']]
    ).fetchall()
    con.close()
    if posts:
        return render_template('editor.html', active='editor', posts=posts)
    else:
        error = "You have not posted any post yet"
        flash(error, 'error')
        return render_template('create.html', active='editor')


# Create page
@app.route('/create', methods=('GET', 'POST'))
@logged_in
def create():
    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']

        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            con = db_con()
            con.execute(
                'INSERT INTO posts (author_id, title, body)'
                ' VALUES (?, ?, ?)',
                [session['user_id'], title, body]
            )
            con.commit()
            con.close()
            return redirect(url_for('all_posts'))

    return render_template('create.html', active='editor')


# Edit post
@app.route('/edit/<string:id>', methods=('GET', 'POST'))
@logged_in
def edit(id):
    """
    """

    con = db_con()
    post = con.execute('SELECT * FROM posts WHERE id = ?', [id]).fetchone()
    con.close()

    if post['author_id'] != session['user_id']:
        flash('You are only authorised to edit your posts', 'error')
        return redirect(url_for('editor'))

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            con = db_con()
            post = con.execute(
                'UPDATE posts SET title = ?, body = ?'
                ' WHERE id = ?',
                [title, body, id]
            )
            con.commit()
            con.close()
            return redirect(url_for('editor'))

    return render_template('edit.html', post=post)


# Delete post
@app.route('/delete_article/<string:id>', methods=['POST'])
@logged_in
def delete(id):
    con = db_con()
    con.execute('DELETE FROM posts WHERE id = ?', [id])
    con.commit()
    con.close()

    flash('Article Deleted', 'success')

    return redirect(url_for('editor'))

# Logout function
@app.route('/logout')
@logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


if (__name__) == '__main__':
    app.run(debug=True)
