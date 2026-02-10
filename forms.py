from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, Length, NumberRange, EqualTo, Optional

class LoginForm(FlaskForm):
    login = StringField("Login: ", validators=[DataRequired()])
    psw = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=25)])
    remember = BooleanField("Remember me", default=False)
    submit = SubmitField()
    
class RegForm(FlaskForm):
    email = StringField("Email: ", validators=[Email(), DataRequired()])
    login = StringField("Login: ", validators=[DataRequired()])
    first_name = StringField("First name: ", validators=[DataRequired()])
    last_name = StringField("Last name: ", validators=[DataRequired()])
    psw = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=25)])
    psw_confirm = PasswordField("Confirm password: ", validators=[DataRequired(), Length(min=4, max=25), EqualTo('psw', message="Passwords must match")])
    submit = SubmitField()
    
class CryptoForm(FlaskForm):
    cipher_type = SelectField('Cipher Type', choices=[
        ('caesar', 'Caesar Cipher'),
        ('vigenere', 'Vigenère Cipher'),
        ('aes', 'AES Encryption'),
        ('base64', 'Base64 Encode/Decode'),
        ('sha256', 'SHA-256 Hash'),
        ('sha512', 'SHA-512 Hash'),
        ('md5', 'MD5 Hash')
    ], validators=[DataRequired()])

    operation = SelectField('Operation', choices=[
        ('encrypt', 'Encrypt'),
        ('decrypt', 'Decrypt'),
        ('hash', 'Hash')
    ], validators=[DataRequired()])

    text = StringField('Text to process', validators=[DataRequired(), Length(max=2000)])
    key = StringField('Key / Shift', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Perform Operation')
    