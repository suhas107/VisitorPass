from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email(check_deliverability=False)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm", validators=[DataRequired(), EqualTo("password")])
    role = SelectField("I am a", choices=[("RESIDENT", "Student/Resident"), ("GUARD", "Guard")], validators=[DataRequired()])
    room_number = StringField("Flat Number")
    phone = StringField("Phone")
    guard_code = StringField("Guard Enroll Code")
    email_code = StringField("Resident Enroll Code")
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    # Allow login with admin@visitorpass.local and other non-deliverable domains
    email = StringField("Email", validators=[DataRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class MFAForm(FlaskForm):
    otp = StringField("One-Time Password", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")


class EnableMFAForm(FlaskForm):
    otp = StringField("OTP", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Enable MFA")
