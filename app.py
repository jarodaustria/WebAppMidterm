from enum import unique
from flask import Flask, render_template, redirect, url_for, request, Response
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import cv2

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jarodski'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_BINDS'] = {'crime': 'sqlite:///crime.db'}
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

camera = cv2.VideoCapture(0)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

# Crime database, version 1


class Crime(db.Model):
    __bind_key__ = 'crime'
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    filename = db.Column(db.String(100))
    verify = db.Column(db.Boolean)
    data = db.Column(db.LargeBinary)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=3, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=3, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<h2>Invalid username or password </h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hash_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hash_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1> New user has been created </h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/admin')
def admin():
    users = User.query.all()

    context = {
        'users': users
    }

    return render_template('admin.html', context=context)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/cctv')
@login_required
def cctv():
    return render_template('cctv1.html', name=current_user.username)


@app.route('/notification')
@login_required
def notification():
    return render_template('notification.html', name=current_user.username)

# Crime database, version 1 function


@app.route('/crimes', methods=['GET', 'POST'])
@login_required
def crimes():
    if request.method == "POST":
        file = request.files['file']

        upload = Crime(filename=file.filename, data=file.read())
        db.session.add(upload)
        db.session.commit()
        return f'Uploaded: {file.filename}'

    return render_template('crimes.html', name=current_user.username)

# Camera function


def gen_frames():
    while True:
        success, frame = camera.read()  # read the camera frame
        if not success:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')  # concat frame one by one and show result


@app.route('/feed')
def feed():
    return render_template('cctv1.html')


@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/delete_user/<int:id>')
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('admin'))
    except:
        return '<h1> Failed to delete user. </h1>'


@app.route('/update_user/<int:id>', methods=['GET', 'POST'])
def update_user(id):

    user_to_update = User.query.get_or_404(id)
    form = RegisterForm(obj=user_to_update)

    print("updating user...")

    if request.method == "POST":
        user_to_update.email = request.form['email']
        user_to_update.username = request.form['username']
        hash_password = generate_password_hash(
            request.form['password'], method='sha256')

        user_to_update.password = hash_password
        print("hindi pa committed")

        try:
            db.session.commit()
            print("committed na")
            return redirect(url_for('admin'))
        except:
            return '<h1> Failed to update user. </h1>'
    else:
        return render_template('update_user.html', form=form, user_to_update=user_to_update)


if __name__ == '__main__':
    db.create_all()
    app.run(host="0.0.0.0", port=8080, debug=True)
