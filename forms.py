from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from email_validator import validate_email
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterUser(FlaskForm):
    name = StringField("User Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")

class CommentForm(FlaskForm):
    body= CKEditorField()
    submit= SubmitField("Post")