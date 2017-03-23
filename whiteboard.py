# -*- coding: utf-8 -*-
import datetime
from hashlib import md5

import pytz
from flask import Flask, request, session, url_for, redirect, \
    render_template, abort, g, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId


app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'social'
app.config['MONGO_URI'] = 'mongodb://razik:razik@ds137090.mlab.com:37090/social'


mongo = PyMongo(app)

app.config.update(dict(
    DEBUG=True,
    SECRET_KEY='development key'))


def get_user_id(username):
    """method to look up the id for a username."""
    rv = mongo.db.user.find_one({'username': username}, {'_id': 1})
    return rv['_id'] if rv else None

def get_user_id_by_email(email):
    """method to look up the id for a email."""
    rv = mongo.db.user.find_one({'email': email}, {'_id': 1})
    return rv['_id'] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return timestamp.replace(tzinfo=pytz.utc).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = mongo.db.user.find_one({'_id': ObjectId(session['user_id'])})


@app.route('/')
def timeline():
    """
    Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    followed = mongo.db.follower.find_one(
        {'who_id': ObjectId(session['user_id'])}, {'whom_id': 1})
    if followed is None:
        followed = {'whom_id': []}
    messages = mongo.db.message.find(
        {'$or': [
            {'author_id': ObjectId(session['user_id'])},
            {'author_id': {'$in': followed['whom_id']}}
        ]}).sort('pub_date', -1)
    return render_template('timeline.html', messages=messages)


@app.route('/public')
def public_timeline():
    """Displays all posts."""
    messages = mongo.db.message.find().sort('pub_date', -1)
    return render_template('timeline.html', messages=messages)


@app.route('/<username>')
def user_timeline(username):
    """Display's a users posts."""
    profile_user = mongo.db.user.find_one({'username': username})
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = mongo.db.follower.find_one(
            {'who_id': ObjectId(session['user_id']),
             'whom_id': {'$in': [ObjectId(profile_user['_id'])]}}) is not None
    messages = mongo.db.message.find(
        {'author_id': ObjectId(profile_user['_id'])}).sort('pub_date', -1)
    return render_template('timeline.html', messages=messages,
                           followed=followed, profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Add the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    mongo.db.follower.update(
        {'who_id': ObjectId(session['user_id'])},
        {'$push': {'whom_id': whom_id}}, upsert=True)
    flash('You are now following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    mongo.db.follower.update(
        {'who_id': ObjectId(session['user_id'])},
        {'$pull': {'whom_id': whom_id}})
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_post', methods=['POST'])
def add_post():
    """Add a new post."""

    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        user = mongo.db.user.find_one(
            {'_id': ObjectId(session['user_id'])}, {'email': 1, 'username': 1})
        mongo.db.message.insert(
            {'author_id': ObjectId(session['user_id']),
             'email': user['email'],
             'username': user['username'],
             'text': request.form['text'],
             'pub_date': datetime.datetime.utcnow()})
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = mongo.db.user.find_one({'username': request.form['username']})
        if user is None:
            error = 'Invalid username or password'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid username or password'
        else:
            flash('You were logged in')
            session['user_id'] = str(user['_id'])
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id_by_email(request.form['email']) is not None:
            error = 'The email is already exist'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            mongo.db.user.insert(
                {'username': request.form['username'],
                 'email': request.form['email'],
                 'pw_hash': generate_password_hash(request.form['password'])})
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Log out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))
'''
@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    """delete user"""
    if g.user:
        if 'user_id' not in session:
            abort(401)
        user = mongo.db.user.find_one(
            {'_id': ObjectId(session['user_id'])}, {'username': 1, 'password': 1})
        print("1+")
        print(user)
        if request.method == 'POST':
            print("reqst post")
            user2 = mongo.db.user.find_one({'username': request.form['username']})
            print("2+")
            print(user)
            if user2 is None or user2['username'] != user['username']:
                error = 'Invalid username'
            elif not check_password_hash(user2['pw_hash'], request.form['password']):
                error = 'Invalid password'
            else:
                print("pass")
                post_delete = mongo.db.message.delete_many({'author_id': ObjectId(session['user_id'])})
                user_delet = mongo.db.user.delete_one({'_id': ObjectId(session['user_id'])})
                flash('Your account are deleted')
                return redirect(url_for('public_timeline'))
    return redirect(url_for('public_timeline'))
'''


app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    app.run(port=33507)
