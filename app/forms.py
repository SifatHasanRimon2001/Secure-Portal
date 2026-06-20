from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    TextAreaField,
    SubmitField
)
from wtforms.validators import (
    DataRequired,
    Length,
    EqualTo,
    Regexp
)
class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30)
        ]
    )
    display_name = StringField(
        "Display Name",
        validators=[
            DataRequired(),
            Length(min=2, max=50)
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128),
            Regexp(
                r".*[A-Z].*",
                message="Uppercase required."
            ),
            Regexp(
                r".*[a-z].*",
                message="Lowercase required."
            ),
            Regexp(
                r".*\d.*",
                message="Number required."
            ),
            Regexp(
                r".*[^A-Za-z0-9].*",
                message="Special character required."
            )
        ]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo(
                "password",
                message="Passwords must match."
            )
        ]
    )
    submit = SubmitField(
        "Create Account"
    )
class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired()
        ]
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired()
        ]
    )
    submit = SubmitField(
        "Login"
    )
class PostForm(FlaskForm):
    content = TextAreaField(
        "Secure Message",
        validators=[
            DataRequired(),
            Length(max=5000)
        ]
    )
    submit = SubmitField(
        "Encrypt & Save"
    )
class CredentialCheckForm(FlaskForm):
    password = PasswordField(
        "Password",
        validators=[
            DataRequired()
        ]
    )
    submit = SubmitField(
        "Verify"
    )