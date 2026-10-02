from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, FloatField
from wtforms.validators import DataRequired, Optional, NumberRange

# Определение класса формы
class SettingsForm(FlaskForm):
    user_id = StringField('Username', validators=[DataRequired()])
    user_password = StringField('Password', validators=[DataRequired()])
    client_id = StringField('Client ID', validators=[DataRequired()])
    client_secret = StringField('Client secret', validators=[DataRequired()])
    client_key = StringField('Client key')
    skill_id = StringField('Skill ID')
    batch_state_enabled = BooleanField('Batch state reporting')
    batch_state_debounce = FloatField(
        'Debounce (sec)',
        default=2.0,
        validators=[Optional(), NumberRange(min=0.2, max=120)],
    )
    submit = SubmitField('Submit')
