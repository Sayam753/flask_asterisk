import time
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

from flask import Flask, url_for, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy

# For forms
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_login import UserMixin, LoginManager, login_user, current_user, login_required, logout_user
from flask_bcrypt import Bcrypt


# Initialize the flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = '99f625427e95c4dbafe99f1d6e73abfd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User(email: {self.email})"


class UserLoginForm(FlaskForm):
    email = StringField("Email",
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RegistrationForm(FlaskForm):
    username = StringField("Username",
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField("Email",
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password",
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one')


# Reload the user from its session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash(f"You are already logged in!", "warning")
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f"You account has been created! You are now able to log in", "success")
        return redirect(url_for('login'))
    return render_template("register.html", title="Register", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash(f"You are already logged in!", "warning")
        return redirect(url_for('home'))
    form = UserLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        flash(f"Login unsuccessful! Please check email and password!", "danger")
    return render_template("login.html", form=form)


@app.route("/list-users")
@login_required
def list_users():
    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    storeID = db.Column(db.String(30), nullable=False)
    nexmoDID = db.Column(db.String(30), nullable=False)
    apiServer = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return f"Route(storeID: {self.storeID}, nexmoDID: {self.nexmoDID}, apiServer: {self.apiServer})"


class RouteForm(FlaskForm):
    storeID = StringField("storeID", validators=[DataRequired()])
    nexmoDID = StringField("nexmoDID", validators=[DataRequired()])
    apiServer = StringField("apiServer", validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route('/')
def home():
    routes = Route.query.all()
    return render_template("home.html", routes=routes)


@app.route('/route/new', methods=['GET', 'POST'])
@login_required
def new_route():
    form = RouteForm()
    if form.validate_on_submit():
        route = Route(storeID=form.storeID.data,
                      nexmoDID=form.nexmoDID.data, apiServer=form.apiServer.data)
        db.session.add(route)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("route.html", form=form, info="Create new Route")


@app.route('/route/<int:route_id>/update', methods=['GET', 'POST'])
@login_required
def update_route(route_id):
    route = Route.query.get(route_id)
    form = RouteForm()
    if form.validate_on_submit():
        route.storeID = form.storeID.data
        route.nexmoDID = form.nexmoDID.data
        route.apiServer = form.apiServer.data
        db.session.commit()
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.storeID.data = route.storeID
        form.nexmoDID.data = route.nexmoDID
        form.apiServer.data = route.apiServer
    return render_template('route.html', form=form, info="Update Route")


@app.route('/route/<int:route_id>/delete', methods=['POST'])
@login_required
def delete_route(route_id):
    route = Route.query.get(route_id)
    db.session.delete(route)
    db.session.commit()
    return redirect(url_for('home'))


def print_date_time():
    print(time.strftime("%A, %d. %B %Y %I:%M:%S %p"))


# scheduler = BackgroundScheduler()
# scheduler.add_job(func=print_date_time, trigger="interval", seconds=5)
# scheduler.start()

# Shut down the scheduler when exiting the app
# atexit.register(lambda: scheduler.shutdown())

if __name__ == "__main__":
    app.run(debug=True)
