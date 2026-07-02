from wtforms import (
    Form,
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


class BaseForm(Form):
    """Base form that provides ``hidden_tag()`` (removed in WTForms 3.x).

    Templates inherited from Flask-WTF expect this method to exist, so we
    restore it here as a no-op since CSRF is handled by the session middleware.
    """

    def hidden_tag(self):
        return ""


class RegisterForm(BaseForm):
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
    submit = SubmitField("Create Account")


class LoginForm(BaseForm):
    username = StringField(
        "Username",
        validators=[DataRequired()]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )
    submit = SubmitField("Login")


class PostForm(BaseForm):
    content = TextAreaField(
        "Secure Message",
        validators=[
            DataRequired(),
            Length(max=5000)
        ]
    )
    submit = SubmitField("Encrypt & Save")


class CredentialCheckForm(BaseForm):
    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )
    submit = SubmitField("Verify")
