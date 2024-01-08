from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from datetime import datetime, timedelta
from user_agents import parse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vinayratna123' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/shorten_url'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(10000), nullable=False)

class Url(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(10000), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clicks = db.Column(db.Integer, default=0)
    browsers = db.Column(db.String(1000), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expiration_time = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=2))

    def is_valid(self):
        return self.expiration_time > datetime.utcnow()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class DashboardForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    custom_name = StringField('Custom Name (Optional)')
    submit = SubmitField('Shorten URL')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DashboardForm()
    if form.validate_on_submit():
        # Generate short URL and store information in the database
        short_url = generate_short_url()
        new_url = Url(
            original_url=form.url.data,
            short_url=short_url,
            user_id=current_user.id,
            expiration_time=datetime.utcnow() + timedelta(days=2)
        )
        db.session.add(new_url)
        db.session.commit()
        flash(f'Shortened URL: {url_for("redirect_to_original", short_url=short_url, _external=True)}', 'success')
    return render_template('dashboard.html', form=form, username=current_user.username)

@app.route('/<short_url>')
def redirect_to_original(short_url):
    url = Url.query.filter_by(short_url=short_url).first()

    if url and url.is_valid():
        # Check expiration time
        if url.expiration_time > datetime.utcnow():
            # Increment click count and update last click timestamp
            url.clicks += 1
            url.last_click_at = datetime.utcnow()

            # Get browser information using Flask-UserAgents
            user_agent_string = request.user_agent.string
            user_agent = parse(user_agent_string)

            # Extracted attributes
            browser_info = user_agent.browser.family

            app.logger.debug(f"Queried URL object: {url}")

            if url.browsers is None:
                url.browsers = ""

            if browser_info not in url.browsers:
                # Append the new browser information
                app.logger.debug(f"Before updating browsers: {url.browsers}")
                url.browsers += f", {browser_info}" if url.browsers else browser_info
                app.logger.debug(f"After updating browsers: {url.browsers}")
                db.session.commit()

            return redirect(url.original_url)
        else:
            flash('This short URL has expired.', 'danger')
    else:
        flash(f"{short_url} cannot be shortened. Try again with a different URL.", 'danger')

    return redirect(url_for('dashboard'))


def generate_short_url():
    # Implement your logic to generate a unique short URL here
    # For simplicity, let's use a random string of length 5
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=5))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=4, max=20)])
    submit = SubmitField('Sign Up')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


def create_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_db()
    app.run(debug=True)
