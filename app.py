from flask import Flask, render_template, url_for, request, redirect, session, flash, jsonify, abort, render_template_string
from flask_login import UserMixin, login_user, logout_user, login_required, current_user, LoginManager
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session
import sqlite3 
import random
import string
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Optional
import uuid
from functools import wraps 
from itsdangerous import URLSafeTimedSerializer, BadSignature
from flask_mail import Message, Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
#app.config['MAIL_USERNAME'] = 'Bologna Nel Pallone'
#app.config['MAIL_PASSWORD'] = 'RovesciaIlTortellino123'
app.config['MAIL_DEFAULT_SENDER'] = 'bolognanelpallone@gmail.com'
mail=Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, default = str(uuid.uuid4()))
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    numero = db.Column(db.Integer, index=True, unique=True)
    password_hash = db.Column(db.String(128))
    joined_at=db.Column(db.DateTime(),index=True,default=datetime.utcnow)
    role = db.Column(db.String(64), default="user")
    confirmed = db.Column(db.Boolean, default=False)
    subscriptions = db.relationship('Subscription',back_populates='user')
    slots = db.relationship('Slot', back_populates='gestore')
    referral_code = db.Column(db.String(10), unique=True, nullable=True)
    referred_by_code = db.Column(db.String(10), db.ForeignKey('user.referral_code'))
    referred_by = db.relationship('User', remote_side=[referral_code])
    bonus = db.Column(db.Integer, default=0)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def increase_bonus(self, amount=1):
        self.bonus += amount
        db.session.commit()

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    numero = IntegerField('Numero di cellulare', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    referral_code = StringField('Referral Code', validators=[Optional()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class Slot(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    data = db.Column(db.String(10))
    orario = db.Column(db.String(5))
    posti_disponibili = db.Column(db.Integer)
    subscribers = db.relationship('Subscription', back_populates='slot')
    gestore_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    gestore = db.relationship('User', back_populates='slots')

class SlotForm(FlaskForm):
    data = StringField('Data', validators=[DataRequired()])
    orario = StringField('Orario', validators=[DataRequired()])
    posti_disponibili = IntegerField('Posti Disponibili', validators=[DataRequired()])
    submit = SubmitField('Aggiungi Slot')

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slot_id = db.Column(db.Integer, db.ForeignKey('slot.id'))
    user_numero = db.Column(db.Integer, db.ForeignKey('user.numero'))
    prenotato_il = db.Column(db.DateTime, default=datetime.utcnow)
    numero_persone = db.Column(db.Integer, default=1)
    
    user = db.relationship('User', back_populates='subscriptions')
    slot = db.relationship('Slot', back_populates='subscribers')


def db_connection():
    con = None
    
    try:
        con = sqlite3.connect('user.db')
    except Exception as e:
        print(e)
    return con



@app.route("/", methods = ['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/prenota_slot', methods=['GET', 'POST'])
@login_required
def prenota_slot():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        slot_id = request.form.get('slot_id')
        numero_persone = int(request.form.get('numero_persone'))

        slot = Slot.query.get(slot_id)
    
        if slot:
            print(f"Available Spots Before: {slot.posti_disponibili}")
            if slot.posti_disponibili >= numero_persone:
                subscription = Subscription(user=current_user, slot=slot, numero_persone = numero_persone)
                slot.posti_disponibili -= numero_persone
                db.session.add(subscription)
                db.session.commit()
                print("Spots Decremented!")
                flash('Prenotazione effettuata con successo!', 'success')
            else:
                print("Not Enough Available Spots!")
                flash('Prenotazione non disponibile per questo slot.', 'danger')
        else:
            print("Slot Not Found!")
            flash('Slot non trovato.', 'danger')
        return redirect(url_for('index')) 
    return render_template('prenota_slot.html')

@app.route('/disdici_prenotazione/<int:subscription_id>', methods=['GET', 'POST'])
@login_required
def disdici_prenotazione(subscription_id):
    subscription = Subscription.query.get(subscription_id)
    
    if subscription and subscription.user_numero == current_user.numero:
        slot = subscription.slot
        slot.posti_disponibili += 1
        db.session.delete(subscription)
        db.session.commit()
        flash('Prenotazione disdetta con successo!', 'success')
    else:
        flash('Errore nella disdetta della prenotazione.', 'danger')
    
    return redirect(url_for('profile'))


@app.route('/get_available_slots', methods=['GET', 'POST'])

def get_available_slots():
    available_slots = Slot.query.filter(Slot.posti_disponibili > 0).all()
    print("Available Slots:", available_slots)
    events = []

    for slot in available_slots:
        event = {
            'id': slot.id,
            'data': slot.data,
            'orario': slot.orario,
            'title': f'Slot {slot.id}',
            'start': slot.data + ' ' + slot.orario,  
            'end': slot.data + ' ' + slot.orario,    
            'posti_disponibili': slot.posti_disponibili
        }
        events.append(event)

    return jsonify(events)


@app.route("/contatti")
def contatti():
    return render_template("contatti.html")

@app.route("/chisiamo")
def chi_siamo():
    return render_template("chisiamo.html")

def admin_login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role == 'user':
            return abort(403)
        return func(*args, **kwargs)
    return decorated_view

@app.route('/admin/slot_management', methods=['GET', 'POST'])
@admin_login_required
def slot_management():
    print("Inside slot_management view function")  

    form = SlotForm()

    if form.validate_on_submit():
        print("Form submitted successfully")  

        new_slot = Slot(data=form.data.data, orario=form.orario.data, posti_disponibili=form.posti_disponibili.data, gestore=current_user)
        new_slot.gestore = current_user
        db.session.add(new_slot)
        db.session.commit()
        flash('Nuovo slot orario aggiunto con successo!', 'success')

    slots = Slot.query.all() 
    subscriptions = Subscription.query.all()
    print("Number of slots fetched from the database:", len(slots)) 

    return render_template('slot_management.html', form=form, slots=slots, subscriptions=subscriptions)

@app.route('/delete_slot/<int:slot_id>', methods=['POST'])
@login_required
def delete_slot(slot_id):
    slot = Slot.query.get(slot_id)
    if slot:
        db.session.delete(slot)
        db.session.commit()
        flash('Slot eliminato con successo!', 'success')
    else:
        flash('Slot non trovato.', 'danger')
    return redirect(url_for('slot_management'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        referral_code = generate_referral_code()
        referred_by = None

        if form.referral_code.data:
            referred_by = User.query.filter_by(referral_code=form.referral_code.data).first()

        user = User(
            username=form.username.data,
            email=form.email.data,
            numero=form.numero.data,
            referral_code=referral_code
        )
        user.set_password(form.password.data)

        if referred_by:
            user.referred_by_code = form.referral_code.data

        db.session.add(user)
        db.session.commit()

        if referred_by:
            calculate_referral_bonus(referred_by)

        serializer = URLSafeTimedSerializer(app.secret_key)
        token = serializer.dumps(user.id, salt='email-confirmation')
        print(f"Generated Token: {token}")
        confirmation_link = url_for('confirm_email', token=token, _external=True)

        msg = Message('Conferma la tua registrazione', recipients=[user.email])
        msg.html = render_template('email_confirmation.html', confirmation_link=confirmation_link)
        mail.send(msg)

        flash('Registrazione completata. Controlla la tua email per confermare.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

def increase_bonus(self, amount=1):
        self.bonus += amount
        db.session.commit()

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        user_id = serializer.loads(token, salt='email-confirmation', max_age=3600)
    except BadSignature:
        flash('Il link di conferma è scaduto o non valido.', 'danger')
    else:
        with app.app_context():
            user = User.query.get(user_id)
            if user:
                user.confirmed = True
                db.session.commit()
                flash('Conferma dell\'email riuscita. Ora puoi effettuare l\'accesso.', 'success')
            else:
                flash('Utente non trovato.', 'danger')
    return redirect(url_for('login'))

def generate_referral_code():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(6))

def calculate_referral_bonus(referrer):
    referred_users = User.query.filter_by(referred_by=referrer).all()
    referred_users_with_bookings = 0

    for referred_user in referred_users:
        if Subscription.query.filter_by(user_numero=referred_user.numero).count() > 0:
            referred_users_with_bookings += 1

    referrer.increase_bonus(referred_users_with_bookings // 3)



@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    message = None

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if user.confirmed:  
                login_user(user)
                message = 'Login successful!'
                print('Success message:', message)
                return redirect(url_for('profile'))
            else:
                message = 'Account not confirmed. Please check your email for confirmation instructions.'
                print('Error message:', message)
        else:
            message = 'Invalid username or password'
            print('Error message:', message)

    print('Current message:', message)
    return render_template('login.html', form=form, message=message)

@app.route('/profile')
@login_required  
def profile():
    user = current_user  
    subscriptions = Subscription.query.filter_by(user_numero=user.numero).all() 
    bonus = calculate_referral_bonus(user)
    return render_template('profile.html', user=current_user, subscriptions=subscriptions, bonus=bonus)


@app.route('/forgotpassword', methods = ['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        username = request.form.get('username')
        new = request.form.get('newpassword')
        confirm = request.form.get('newpassword')
        con = db_connection()
        cursor = con.cursor()
        cursor.execute("select * from userData")
        error = "username non esiste"
        for i in cursor:
            if i[0] == username:
                error = 'Password non combaciano'
                if new == confirm:
                    cursor.execute("update userData set password=? where username=?")
                    con.commit()
                    con.close()
                    return render_template('forgotpassword.html', error='Cambiata')
            else:
                con.close()
                return render_template('forgotpassword.html', error = error)
    return render_template('forgotpassword.html')

@app.route('/logout')
def logout():
    session.clear()
    return render_template("index.html")



if __name__ == "__main__":
    with app.app_context():
        # Create the database tables
        db.create_all()
    app.run(debug=True)
