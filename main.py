from flask import Flask, render_template, flash , redirect, url_for, request, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_wtf import FlaskForm
import os


from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import EqualTo, DataRequired, Length, ValidationError
import email_validator

app = Flask(__name__)
app.config["SECRET_KEY"] = 'sathish' #os.environ.get('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///project23.db'#os.environ.get('DATABASE_URI','sqlite:///project23.db')

db = SQLAlchemy(app)
bcrypt = Bcrypt()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category= 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(250), unique=True, nullable = False)
    password = db.Column(db.String(250), nullable = False)
    profile_image = db.Column(db.String(20), default = "default.jpg")
    posts = db.relationship("Post", backref = 'author', lazy = True)

class Post (db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(200), nullable = False)
    content = db.Column(db.Text, nullable = False)
    posted_date = db.Column(db.DateTime, default = datetime.utcnow )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)

db.create_all()



class LoginForm (FlaskForm):
    email = StringField("Enter your email : ", validators=[ DataRequired()])
    password = PasswordField("Enter your password ", validators=[ DataRequired()])
    submit = SubmitField("Login")


class SignForm(FlaskForm):
    username = StringField(label="Enter your name", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField(label="Enter your email ", validators=[ DataRequired() ])
    password = PasswordField("Enter your password", validators=[ DataRequired()])
    confirm_password = PasswordField(label="Re-enter your password : ", validators=[ DataRequired(), EqualTo("password")])
    submit = SubmitField("Sign In ")

    def validate_email(self, email):
        user = User.query.filter_by(email = email.data).first()
        if user:
            raise ValidationError("email is already taken ")



class UpdateForm(FlaskForm):
    username = StringField(label="Enter your name", validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField(label="Enter your email ", validators=[ DataRequired()])
    # profile_pic = FileField(label="choose profile", validators=[FileAllowed("Jpf","png")] )
    submit = SubmitField("Update ")

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email = email.data).first()
            if user:
                raise ValidationError("email is already taken ")




class PostForm (FlaskForm):
    title = StringField("Enter  title : ", validators=[ DataRequired()])
    content = TextAreaField("Contents ", validators=[ DataRequired()])
    submit = SubmitField("Add")

class ResetRequestForm(FlaskForm):
    email = StringField("Enter your email: ", validators=[ DataRequired()])
    submit = SubmitField("Request Password Reset")
    def validate_email(self, email):
        if email.data != current_user.email:

            raise ValidationError("email does not match")


class ChangePassword(FlaskForm):
    password = PasswordField("Enter new password ", validators=[ DataRequired()])
    confirm_password = PasswordField("confirm password ", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Request Password change")

@app.route("/" )
def home():
    page = request.args.get('page', 1, type=int)
    post = Post.query.order_by(Post.posted_date.desc()).paginate(per_page=4)
    photo = '../static/default.png'
    return render_template("home.html", user = current_user, posts = post , photo  = photo)

@app.route("/sign", methods = [ "POST", "GET" ])
def sign():

    form = SignForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username = username ,
                    email = email,
                    password = hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("your account successfully created !!", "success")
        return redirect(url_for('home'))
    return render_template("sign.html", form = form , user= current_user)


@app.route("/login", methods = [ "POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email = email ).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('your have succesffuly looged in ', 'success')
            return redirect(next_page) if next_page else  redirect(url_for('home'))
        elif user:
            flash('password is incorrect', 'warning')
            return redirect(url_for('login'))
        else:
            flash("you dont have an account ", 'warning')
            return redirect(url_for('login'))
    return render_template("login.html", form = form , user = current_user)



@app.route('/logout', methods = [ "POST", "GET"])
@login_required
def logout():
    logout_user()
    flash("you have been logout ", 'success')
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    photo = '../static/default.png'
    return render_template("account.html", user = current_user, photo = photo)


@app.route("/update", methods = [ "POST", "GET"])
@login_required
def update():
    form = UpdateForm()
    if form.validate_on_submit():
        email = form.email.data
        username  = form.username.data
        current_user.email = email
        current_user.username = username
        db.session.commit()
        flash("your account have been updated ", "success")
        return redirect(url_for("account"))
    elif request.method == "GET":
        form.email.data = current_user.email
        form.username.data = current_user.username

    return render_template('update.html', form = form , user = current_user)

@app.route("/post", methods = [ "POST", "GET"])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title = form.title.data,
                        content = form.content.data,
                        author = current_user)
        db.session.add(new_post)
        db.session.commit()

        flash("post created ! ", "success")
        return redirect(url_for("home"))
    return render_template("post.html", form = form, user = current_user)

@app.route("/blogs/<id>")

def blogs(id):
    post = Post.query.get(id)
    photo = '../static/default.png'
    return render_template("blogs.html", post = post, user = current_user, photo = photo)

@app.route("/blogupdate/<process_id>", methods = [ "POST", "GET"] )
@login_required
def update_blog(process_id):

    post = Post.query.get(process_id)
    if current_user.id != post.author.id:
        abort(403)
    photo = '../static/default.png'
    form = PostForm()

    if form.validate_on_submit():
            post.title = form.title.data
            post.content = form.content.data
            db.session.commit()
            flash("Updated succesffully", "success")
            return redirect(url_for('blogs', id = post.id))
    elif request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content

    return render_template("blog_update.html", user = current_user, form = form)

@app.route("/blogdelete/<process_id>", methods = [ "POST", "GET"] )
@login_required
def delete_blog(process_id):
    post = Post.query.get(process_id)
    if current_user.id != post.author.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("blog deleted successfully", "success")
    return redirect(url_for("home"))

@app.route("/userblog/<user_id>", methods = [ "POST", "GET"] )
@login_required
def user_post(user_id):
    page = request.args.get('page_no' ,1, type=int)
    user =User.query.filter_by(id=user_id).first()
    post = Post.query.filter_by(user_id = user.id).order_by(Post.posted_date.desc()).\
        paginate(per_page=3)
    photo = '../static/default.png'
    for posts in post.items:
        name =  posts.author.username
        break


    return render_template("user_post.html", user = current_user, posts = post,page = page,  photo = photo, name = name)

@app.route("/resetrequest", methods = [ 'POST', 'GET'])
@login_required
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        # send_mail(form.email.data)
        return redirect(url_for("change_password"))
    return render_template('reset_request.html', form = form , user = current_user)

@app.route("/changepassword", methods =[ 'POST', 'GET'])
@login_required
def change_password():
    form = ChangePassword()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User.query.filter_by(id = current_user.id).first()
        if user:
            user.password = hashed_password
            db.session.commit()
            flash("password changed successfully", "success")
            return redirect(url_for('login'))
    return render_template('change_password.html', form = form, user = current_user)


if __name__ == "__main__":
    app.run(debug=True)
