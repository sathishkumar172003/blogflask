from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, EmailField, PasswordField, validators
from wtforms.validators import EqualTo, DataRequired, Length, Email, ValidationError
import email_validator

#
# class SignForm(FlaskForm):
#     username = StringField(label="Enter your name", validators=[DataRequired(), Length(min=2, max=50)])
#     email = EmailField(label="Enter your email ", validators=[ DataRequired(), Email() ])
#     password = PasswordField("Enter your password", validators=[ DataRequired()])
#     confirm_password = PasswordField(label="Re-enter your password : ", validators=[ DataRequired(), EqualTo("password")])
#     submit = SubmitField("Sign In ")
#
#     def validate_email(self, email):
#         user = User.query.filter_by(email = email.data).first()
#         if user:
#             raise ValidationError("email is already taken ")
#
#
# class LoginForm (FlaskForm):
#     email = EmailField("Enter your email : ", validators=[ DataRequired(), Email()])
#     password = PasswordField("Enter your password ", validators=[ DataRequired()])
#     submit = SubmitField("Login")

    # def validate_password(self,  password):
    #     user = User.query.filter_by(email = self.email.data).first()
    #     if bcrypt.check_password_hash(user.password, password):
    #         pass
    #     else:
    #         raise ValidationError("password doesn't match")
    #
    # def validate_email (self, email):
    #     user = User.query.filter_by(email = email.data).first()
    #     if user:
    #         pass
    #     else:
    #         raise ValidationError("email  doesn't exists")