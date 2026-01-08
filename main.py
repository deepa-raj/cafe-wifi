from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, IntegerField, DecimalField, \
    FileField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, URL
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask import abort
from flask_login import current_user


# save "cafes.db" in the instance folder

app = Flask(__name__)
app.config["SECRET_KEY"] = 'YOUR KEY HERE'
csrf = CSRFProtect(app)
Bootstrap5(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///cafes.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(500), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String(100), nullable=False)
    coffee_price = db.Column(db.String(100), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    # role = db.Column(db.String(50), nullable=False, default='user')  # user or admin

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)



class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CafeForm(FlaskForm):
    name = StringField('Cafe Name', validators=[DataRequired()])
    location_url = StringField('Location URL', validators=[DataRequired(), URL()])
    image = FileField('Image Upload')
    hidden_image = HiddenField()
    wifi = BooleanField('Wi-Fi')
    toilet = BooleanField('Toilet')
    power_supply = BooleanField('Power Supply')
    seat_range = StringField('Seat Range')
    coffee_price = StringField('Coffee Price')
    submit = SubmitField('Submit Changes')


class AddCafeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    location_url = StringField('Location URL', validators=[Optional(), URL()])
    image_upload = StringField('Image Upload', validators=[Optional(), URL()])
    wifi = BooleanField('Wi-Fi')
    toilet = BooleanField('Toilet')
    power_supply = BooleanField('Power Supply')
    seats = IntegerField('Seats')
    price = DecimalField('Coffee Price', places=2)
    submit = SubmitField('Add Cafe')


class EditCafeForm(FlaskForm):
    name = StringField('Cafe Name', validators=[DataRequired()])
    map_url = StringField('Map URL', validators=[DataRequired(), URL()])
    img_url = StringField('Image URL', validators=[DataRequired(), URL()])
    location = StringField('Location', validators=[DataRequired()])
    has_sockets = BooleanField('Has Sockets')
    has_toilet = BooleanField('Has Toilet')
    has_wifi = BooleanField('Has WiFi')
    can_take_calls = BooleanField('Can Take Calls')
    seats = StringField('Seats')
    coffee_price = StringField('Coffee Price')
    submit = SubmitField('Submit Changes')


csrf = CSRFProtect(app)
class CSRFProtectionForm(FlaskForm):
    submit = SubmitField('Delete Cafe')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if not current_user.is_authenticated or current_user.role != 'admin':
#             abort(403)
#         return f(*args, **kwargs)
#     return decorated_function



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print("Form is valid")
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is None:
            print("Creating new user")
            new_user = User(email=form.email.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)  # Log in the user after registration
            return redirect(url_for('edit'))
        else:
            print("User already exists")
            flash('A user with that email already exists.')
    else:
        print("Form is not valid")
        print(form.errors)
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))

    form = LoginForm()
    errors = []
    if form.validate_on_submit():
        print("Form is valid")
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            print("Logging in user")
            login_user(user)
            next_url = session.get('next_url', url_for('home'))
            session.pop('next_url', None)  # Remove the next_url from session after using it
            return redirect(next_url)
        else:
            print("Invalid email or password")
            errors.append('Invalid email or password.')

    else:
        print("Form is not valid")
        print(form.errors)

    if request.args.get('next'):
        session['next_url'] = request.args.get('next', url_for('home'))

    return render_template('login.html', form=form, errors=errors)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


class UpdateForm(FlaskForm):
    rating = SelectField("Your Rating out of 10 e.g. 7.5")
    review = StringField("Your Review")
    submit = SubmitField("Done")


@app.route("/")
def home():
    result = db.session.execute(db.select(Cafe).order_by(Cafe.name))
    all_cafes = result.scalars().all()
    return render_template("index.html", cafes=all_cafes)



@app.route('/cafe/<int:cafe_id>', methods=['GET', 'POST'])
def cafe_detail(cafe_id):
    cafe = Cafe.query.get_or_404(cafe_id)
    csrf_form = CSRFProtectionForm()
    return render_template('cafe_detail.html', cafe=cafe, csrf_form=csrf_form)



@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_cafe():
    form = EditCafeForm()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            has_sockets=form.has_sockets.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
            coffee_price=form.coffee_price.data,
        )
        db.session.add(new_cafe)
        db.session.commit()
        flash('Cafe added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_cafe.html', form=form)


@app.route('/edit/<int:cafe_id>', methods=['GET', 'POST'])
@login_required

def edit_cafe(cafe_id):
    cafe = Cafe.query.get_or_404(cafe_id)
    form = EditCafeForm(obj=cafe)

    if form.validate_on_submit():
        cafe.name = form.name.data
        cafe.map_url = form.map_url.data
        cafe.img_url = form.img_url.data
        cafe.location = form.location.data
        cafe.has_sockets = form.has_sockets.data
        cafe.has_toilet = form.has_toilet.data
        cafe.has_wifi = form.has_wifi.data
        cafe.can_take_calls = form.can_take_calls.data
        cafe.seats = form.seats.data
        cafe.coffee_price = form.coffee_price.data

        db.session.commit()
        flash('Cafe updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('edit.html', form=form, cafe=cafe)


@app.route('/delete/<int:cafe_id>', methods=['POST'])
@login_required
# @admin_required
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get_or_404(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    flash('Cafe has been deleted successfully!', 'success')
    return redirect(url_for('home'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
