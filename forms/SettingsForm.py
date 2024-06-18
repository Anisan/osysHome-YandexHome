from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired

# Определение класса формы
class SettingsForm(FlaskForm):
    user_id = StringField('Username', validators=[DataRequired()])
    user_password = StringField('Password', validators=[DataRequired()])
    client_id = StringField('Client ID', validators=[DataRequired()])
    client_secret = StringField('Client secret', validators=[DataRequired()])
    client_key = StringField('Client key')
    skill_id = StringField('Skill ID')
    submit = SubmitField('Submit')