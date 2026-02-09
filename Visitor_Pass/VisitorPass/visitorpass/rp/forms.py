from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateTimeLocalField
from wtforms.validators import DataRequired


class CreatePassForm(FlaskForm):
    visitor_name = StringField("Visitor Name", validators=[DataRequired()])
    visitor_phone = StringField("Visitor Phone", validators=[DataRequired()])
    valid_from = DateTimeLocalField("Valid From", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    valid_until = DateTimeLocalField("Valid Until", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    submit = SubmitField("Create Pass")


class TokenVerifyForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired()])
    submit = SubmitField("Verify Token")
