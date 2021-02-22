import random
import string
from flask import render_template, Flask, request, redirect, url_for, flash
from flask_login import LoginManager, current_user, UserMixin, login_user, login_required
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

db = SQLAlchemy(app=app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db0.sqlite3"
app.config["SQLALCHEMY_BINDS"] = {
    'teams': "sqlite:///db1.sqlite3",
    'tasks': "sqlite:///db2.sqlite3"
}
app.config["SECRET_KEY"] = os.urandom(24)

db.init_app(app=app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    team = db.Column(db.String(100))
    role = db.Column(db.String(100))


class Team(db.Model):
    __bind_key__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    members = db.Column(db.String(1000))
    manager = db.Column(db.String(100))
    invite = db.Column(db.String(1000), unique=True)


class Task(db.Model):
    __bind_key__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(1000))
    dueto = db.Column(db.String(100))
    foruser = db.Column(db.String(100))
    inteam = db.Column(db.String(100))
    state = db.Column(db.String(50))


loginManager = LoginManager()
loginManager.login_view = "signin"
loginManager.init_app(app=app)


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


@loginManager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def homepage():
    if not current_user.is_authenticated or current_user.team == "None":
        return render_template("index.html", team="None")
    elif current_user.is_authenticated and current_user.team != "None":

        teamusers = Team.query.filter_by(name=current_user.team).first().members.split(",")

        names = []
        for user in teamusers:
            names.append(User.query.filter_by(email=user).first().name)
        roles = []
        for user in teamusers:
            roles.append(User.query.filter_by(email=user).first().role)

        if current_user.role == "Manager":
            return render_template("index.html", names=names, size=len(teamusers), roles=roles,
                                   team=Team.query.filter_by(name=current_user.team).first(),
                                   taskstodo=Task.query.filter_by(inteam=current_user.team, state="todo").all(),
                                   tasksdone=Task.query.filter_by(inteam=current_user.team, state="done").all())
        elif current_user.role == "Worker":
            return render_template("index.html", names=names, size=len(teamusers), roles=roles,
                                   team=Team.query.filter_by(name=current_user.team).first(),
                                   taskstodo=Task.query.filter_by(inteam=current_user.team,
                                                                  state="todo", foruser=current_user.name).all(),
                                   tasksdone=Task.query.filter_by(inteam=current_user.team, state="done",
                                                                  foruser=current_user.name).all())


@app.route("/remove/<id>", methods=['POST'])
def remove_post(id):
    if current_user.is_authenticated and current_user.role == "Manager":
        if Task.query.filter_by(id=id).first().inteam == current_user.team:
            Task.query.filter_by(id=id).delete()
            db.session.commit()
            return redirect(url_for("homepage"))
        return redirect(url_for("homepage"))


@app.route("/setdone/<id>", methods=['POST'])
def setdone_post(id):
    if current_user.is_authenticated and current_user.role == "Worker":
        if Task.query.filter_by(id=id).first().foruser == current_user.name:
            Task.query.filter_by(id=id).first().state = "done"
            db.session.commit()
            return redirect(url_for("homepage"))
        return redirect(url_for("homepage"))


@app.route("/settodo/<id>", methods=['POST'])
def settodo_post(id):
    if current_user.is_authenticated and current_user.role == "Worker":
        if Task.query.filter_by(id=id).first().foruser == current_user.name:
            Task.query.filter_by(id=id).first().state = "done"
            db.session.commit()
            return redirect(url_for("homepage"))
        return redirect(url_for("homepage"))


@app.route("/signin")
def signin():
    return render_template("signin.html")


@app.route("/signin", methods=['POST'])
def signin_post():
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash("Your credentials are incorrect.")
        return redirect(url_for("signin"))

    login_user(user)

    return redirect(url_for("homepage"))


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/signup", methods=['POST'])
def signup_post():
    email = request.form.get("email")
    name = request.form.get("name")
    password = request.form.get("password")

    user = User.query.filter_by(email=email).first()

    if user:
        flash("Email is already taken.")
        return redirect(url_for("signup"))
    elif len(password) < 4:
        flash("Please enter valid password.")
        return redirect(url_for("signup"))
    elif len(name) < 1:
        flash("Please enter valid name.")
        return redirect(url_for("signup"))
    elif len(email) < 3:
        flash("Please enter valid email.")
        return redirect(url_for("signup"))

    new_user = User(email=email, password=generate_password_hash(password, method="sha256"), name=name, team="None",
                    role="None")

    db.session.add(new_user)
    db.session.commit()

    flash("You have been successfully registered.")
    return redirect(url_for("signin"))


@app.route("/createteam")
@login_required
def createteam():
    return render_template("createteam.html")


@app.route("/createteam", methods=['POST'])
@login_required
def createteam_post():
    name = request.form.get("teamname")

    team = Team.query.filter_by(name=name).first()

    if team or name.lower() == "none" or len(name) <= 3:
        flash("This name is already in use.")
        return redirect(url_for("createteam"))

    invitegen = id_generator(size=4)

    if not Team.query.filter_by(invite=invitegen).first():

        new_team = Team(name=name, members=str(current_user.email), manager=str(current_user.email), invite=invitegen)

        db.session.add(new_team)
        db.session.commit()
        user = User.query.filter_by(email=current_user.email).first()
        user.team = name
        user.role = "Manager"
        db.session.commit()

        return redirect(url_for("homepage"))

    else:
        createteam_post()


@app.route("/assigntask")
@login_required
def assigntask():
    return render_template("assigntask.html")


@app.route("/asigntask", methods=['POST'])
@login_required
def assigntask_post():
    if current_user.role == "Manager":
        taskname = request.form.get("taskname")
        dueto = request.form.get("dueto")
        forname = request.form.get("for")

        usersinteam = User.query.filter_by(team=current_user.team).all()

        for user in usersinteam:
            if user.name == forname:
                new_task = Task(task=taskname, dueto=dueto, foruser=forname, inteam=current_user.team, state="todo")
                db.session.add(new_task)
                db.session.commit()
                return redirect(url_for("homepage"))

        flash("Enter a valid user.")
        return redirect(url_for("assigntask"))


@app.route("/invite/<id>")
@login_required
def invite(id):
    team = Team.query.filter_by(invite=id).first()

    if team:
        user = User.query.filter_by(email=current_user.email).first()
        user.role = "Worker"
        user.team = team.name
        team.members += "," + current_user.email
        db.session.commit()

    return redirect(url_for("homepage"))


if __name__ == '__main__':
    app.run(debug=True)
