import email
from enum import unique
from flask import Flask, render_template, redirect, url_for, request, Response, send_file, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import cv2
import tensorflow as tf
from keras.models import load_model
from collections import deque
from moviepy.editor import *
import numpy as np
import os
from io import BytesIO
import jinja2
import threading
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jarodski'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_BINDS'] = {'crime': 'sqlite:///crime.db'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
# thesispd2022@gmail.com
app.config['MAIL_USERNAME'] = 'thesispd2022@gmail.com'
app.config['MAIL_PASSWORD'] = 'group10pd22022'  # group10pd22022
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.jinja_env.globals.update(zip=zip)
camera = cv2.VideoCapture(0)
IMAGE_HEIGHT, IMAGE_WIDTH = 64, 64

SEQUENCE_LENGTH = 30

# classes_list = ["Crime", "Not Crime"]
classes_list = ["Not Crime", "Assault", "Shooting"]
reconstructed_model = load_model(
    "threeClass_90p.hf")


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
    exist_email = User.query.filter_by(email=form.email.data).first()
    exist_username = User.query.filter_by(username=form.username.data).first()
    if (exist_email or exist_username):
        return '<h1> User already exists! </h1>'
    if form.validate_on_submit():
        hash_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account Created!")
        # return '<h1> New user has been created </h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    date_query = db.select([Crime.date_created])
    date = db.session.execute(date_query).fetchall()
    date_list = []
    verify = Crime.query.filter_by(
        verify=True).with_entities(Crime.date_created).all()
    # date_verify = db.select([Crime.verify])
    # verify = db.session.execute(date_verify).fetchall()
    verify_list = []
    # for i in verify:
    #     if i == None:
    #         i = False
    print(date)
    for i in date:
        date_list.append(str((i[0].date())))
    for i in verify:
        verify_list.append(str((i[0].date())))
    print(verify_list)
    date = date_list
    date, detections = np.unique(date_list, return_counts=True)
    verify, verified = np.unique(verify_list, return_counts=True)  # 4-0-1

    date = list(date)
    verify = list(verify)
    verified = list(verified)

    for i in range(len(date)):
        if date[i] not in verify:
            verify.insert(i, date[i])
            verified.insert(i, 0)

    detect = []
    for i in detections:
        detect.append(str(i))
    detections = list(detections)
    ver = []
    for i in verified:  # [4,1] ## [4, 0, 1]
        ver.append(str(i))
    print("Here is the date: ", date)
    print("Here are the detections", detections)
    print("Here are the verified", verified)  # [4, 0, 1]
    data = date + detections + verified
    data = []
    for i in range(len(date)):
        data.append((date[i], detections[i], verified[i]))

    print("data", data)

    labels = [row[0]for row in data]
    values = [row[1] for row in data]
    values1 = [row[2] for row in data]
    # data for dashboard data visualization
    return render_template('dashboard.html', name=current_user.username, labels=labels, values=values, values1=values1)


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
    # IMAGE_HEIGHT, IMAGE_WIDTH = 64, 64
    # SEQUENCE_LENGTH = 30
    # classes_list = ["Crime", "Not Crime"]

    # reconstructed_model = load_model("pdmodel1_morefightingdataset.hf")

    # video_reader = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    # original_video_width = int(video_reader.get(cv2.CAP_PROP_FRAME_WIDTH))
    # original_video_heigth = int(video_reader.get(cv2.CAP_PROP_FRAME_HEIGHT))

    # video_writer = cv2.VideoWriter(out, cv2.VideoWriter_fourcc('M', 'P', '4', 'V'),
    #                                 video_reader.get(cv2.CAP_PROP_FPS), (original_video_width, original_video_heigth))
    # frames_queue = deque(maxlen=SEQUENCE_LENGTH)
    # predicted_class_name = ''
    # predicted_label = []

    # while True:
    #     ok, frame = video_reader.read()

    #     if not ok:
    #         break

    #     frame = cv2.cvtColor(frame,  cv2.COLOR_BGR2GRAY)
    #     resized_frame = cv2.resize(frame, (IMAGE_HEIGHT, IMAGE_WIDTH))

    #     normalized_frame = resized_frame/255

    #     frames_queue.append(normalized_frame)

    #     if len(frames_queue) == SEQUENCE_LENGTH:
    #         print(reconstructed_model.predict(
    #             np.expand_dims(frames_queue, axis=0)))
    #         predicted_labels_probabilities = reconstructed_model.predict(
    #             np.expand_dims(frames_queue, axis=0))[0]

    #         predicted_label = np.argmax(predicted_labels_probabilities)

    #         predicted_class_name = classes_list[predicted_label]
    #         print(predicted_class_name, "-", predicted_label)
    #         cv2.putText(frame, predicted_class_name, (10, 30),
    #                     cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)

    #     cv2.imshow("Video", frame)
    #     if cv2.waitKey(10) & 0xFF == ord('q'):
    #         break

    # video_reader.release()
    # video_writer.release()
    return render_template('cctv1.html', name=current_user.username)


@app.route('/notification')
@login_required
def notification():
    crimes = Crime.query.all()
    total_crimes = len(crimes)
    #crimes = Crime.objects.filter()
    total_unvalidated_crimes = len(crimes)

    context = {
        'crimes': crimes,
        # 'total_crimes': total_crimes,
        'total_unvalidated_crimes': total_unvalidated_crimes,
    }
    j = []
    for x in crimes:
        with open('static/data/data{}.mp4'.format(x.id), 'wb') as f:
            f.write(x.data)
        j.append(x.id)
    print(j)
    return render_template('notification.html', name=current_user.username, context=context, zip=zip, j=j)

# Crime database, version 1 function


@app.route('/crimes', methods=['GET', 'POST'])
@login_required
def crimes():
    if request.method == "POST":
        file = request.files['file']

        upload = Crime(filename=file.filename, data=file.read(), verify=False)
        db.session.add(upload)
        db.session.commit()
        return f'Uploaded: {file.filename}'

    return render_template('crimes.html', name=current_user.username)

# Camera function


def gen_frames():
    video_reader = camera

    frames_queue = deque(maxlen=SEQUENCE_LENGTH)
    cctv1_queue = deque(maxlen=SEQUENCE_LENGTH)
    cctv2_queue = deque(maxlen=SEQUENCE_LENGTH)
    cctv3_queue = deque(maxlen=SEQUENCE_LENGTH)
    cctv4_queue = deque(maxlen=SEQUENCE_LENGTH)

    count = 0
    predicted_class_name = ''
    predicted_label = []
    while True:
        success, frame = camera.read()  # read the camera frame
        if not success:
            break
        else:

            frame = cv2.cvtColor(frame,  cv2.COLOR_BGR2GRAY)
            # Frames
            cctv1 = frame[0:242, 0:310]
            cctv2 = frame[242:484, 0:310]
            cctv3 = frame[0:242, 310:620]
            cctv4 = frame[242:484, 310:620]

            resized_frame = cv2.resize(frame, (IMAGE_HEIGHT, IMAGE_WIDTH))

            resized_cctv1 = cv2.resize(cctv1, (IMAGE_HEIGHT, IMAGE_WIDTH))
            resized_cctv2 = cv2.resize(cctv2, (IMAGE_HEIGHT, IMAGE_WIDTH))
            resized_cctv3 = cv2.resize(cctv3, (IMAGE_HEIGHT, IMAGE_WIDTH))
            resized_cctv4 = cv2.resize(cctv4, (IMAGE_HEIGHT, IMAGE_WIDTH))

            normalized_frame = resized_frame/255

            normalized_cctv1 = resized_cctv1/255
            normalized_cctv2 = resized_cctv2/255
            normalized_cctv3 = resized_cctv3/255
            normalized_cctv4 = resized_cctv4/255

            count = count + 1
            if count == 8:
                frames_queue.append(normalized_frame)
                count = 0

            cctv1_queue.append(normalized_cctv1)
            cctv2_queue.append(normalized_cctv2)
            cctv3_queue.append(normalized_cctv3)
            cctv4_queue.append(normalized_cctv4)

            if len(frames_queue) == SEQUENCE_LENGTH:
                # print(reconstructed_model.predict(
                #     np.expand_dims(frames_queue, axis=0)))

                predicted_labels_probabilities = reconstructed_model.predict(
                    np.expand_dims(frames_queue, axis=0))[0]

                predicted_labels_probabilities_cctv1 = reconstructed_model.predict(
                    np.expand_dims(cctv1_queue, axis=0))[0]
                predicted_labels_probabilities_cctv2 = reconstructed_model.predict(
                    np.expand_dims(cctv2_queue, axis=0))[0]
                predicted_labels_probabilities_cctv3 = reconstructed_model.predict(
                    np.expand_dims(cctv3_queue, axis=0))[0]
                predicted_labels_probabilities_cctv4 = reconstructed_model.predict(
                    np.expand_dims(cctv4_queue, axis=0))[0]

                # class index number
                predicted_label = np.argmax(predicted_labels_probabilities)
                predicted_label_cctv1 = np.argmax(
                    predicted_labels_probabilities_cctv1)
                predicted_label_cctv2 = np.argmax(
                    predicted_labels_probabilities_cctv2)
                predicted_label_cctv3 = np.argmax(
                    predicted_labels_probabilities_cctv3)
                predicted_label_cctv4 = np.argmax(
                    predicted_labels_probabilities_cctv4)
                # class name
                predicted_class_name = classes_list[predicted_label]
                predicted_class_name_cctv1 = classes_list[predicted_label_cctv1]
                predicted_class_name_cctv2 = classes_list[predicted_label_cctv2]
                predicted_class_name_cctv3 = classes_list[predicted_label_cctv3]
                predicted_class_name_cctv4 = classes_list[predicted_label_cctv4]

                # print("cctv1", predicted_class_name_cctv1, "-", predicted_label_cctv1)
                # print("cctv2", predicted_class_name_cctv2, "-", predicted_label_cctv2)
                # print("cctv3", predicted_class_name_cctv3, "-", predicted_label_cctv3)
                # print("cctv4", predicted_class_name_cctv4, "-", predicted_label_cctv4)

                cv2.putText(cctv1, predicted_class_name_cctv1, (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(cctv1, str(predicted_labels_probabilities_cctv1), (10, 60),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)

                cv2.putText(cctv2, predicted_class_name_cctv2, (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(cctv2, str(predicted_labels_probabilities_cctv1), (10, 60),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)

                cv2.putText(cctv3, predicted_class_name_cctv3, (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(cctv3, str(predicted_labels_probabilities_cctv1), (10, 60),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)

                cv2.putText(cctv4, predicted_class_name_cctv4, (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(cctv4, str(predicted_labels_probabilities_cctv1), (10, 60),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 2)

            output_frame_1 = cv2.vconcat((cctv1, cctv2))
            output_frame_2 = cv2.vconcat((cctv3, cctv4))
            output_frame = cv2.hconcat((output_frame_1, output_frame_2))

            ret, buffer = cv2.imencode('.jpg', cctv1)
            output_frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + output_frame + b'\r\n')  # concat frame one by one and show result


@app.route('/feed')
def feed():
    return render_template('cctv1.html')


@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/confirm_emergency/<int:id>')
@login_required
def confirm_emergency(id):
    #user = User.query.all()
    confirm = Crime.query.filter_by(id=id).first()
    confirm.verify = True
    db.session.commit()
    subject = " Emergency for {}".format(current_user.username)
    msg = Message(
        subject=subject,
        sender='thesispd2022@gmail.com',
        # recipients=['kchan01412@gmail.com', 'tyrone.guevarra@gmail.com',
        #             'qjacaustria@tip.edu.ph', 'qaagalit02@tip.edu.ph']
        recipients=['tyrone.guevarra@gmail.com']
    )
    msg.body = 'SA CCTV 1 MAY EMERGENCY BILIS REPORT TO AUTHORITY PLS'

    with app.open_resource('static/data/data{}.mp4'.format(id)) as fp:
        msg.attach('data{}.mp4'.format(id), "video/mp4", fp.read())
    mail.send(msg)
    return redirect(url_for('notification'))


@app.route('/delete_user/<int:id>')
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return redirect(url_for('admin'))
    except:
        return '<h1> Failed to delete user. </h1>'


@app.route('/delete_notif/<int:id>')
@login_required
def delete_notif(id):
    notif_to_delete = Crime.query.get_or_404(id)

    try:
        db.session.delete(notif_to_delete)
        db.session.commit()
        return redirect(url_for('notification'))
    except:
        return '<h1> Failed to delete notif. </h1>'


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
