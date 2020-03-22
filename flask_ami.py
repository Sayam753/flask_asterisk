from flask import Flask, url_for, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy

# For forms
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


# Initialize the flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = '99f625427e95c4dbafe99f1d6e73abfd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)


class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    storeID = db.Column(db.String(30), nullable=False)
    nexmoDID = db.Column(db.String(30), nullable=False)
    apiServer = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return f"Route(storeID: {self.storeID}, nexmoDID: {self.nexmoDID}, apiServer: {self.apiServer})"


class RouteForm(FlaskForm):
    storeID = StringField("storeID", validators=[DataRequired()])
    nexmoDID = StringField("nexmoDID", validators=[DataRequired()])
    apiServer = StringField("apiServer", validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route('/')
def home():
    routes = Route.query.all()
    return render_template("home.html", routes=routes)


@app.route('/route/new', methods=['GET', 'POST'])
def new_route():
    form = RouteForm()
    if form.validate_on_submit():
        route = Route(storeID=form.storeID.data, nexmoDID=form.nexmoDID.data, apiServer=form.apiServer.data)
        db.session.add(route)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("route.html", form=form, info="Create new Route")


@app.route('/route/<int:route_id>/update', methods=['GET', 'POST'])
def update_route(route_id):
    route = Route.query.get(route_id)
    form = RouteForm()
    if form.validate_on_submit():
        route.storeID = form.storeID.data
        route.nexmoDID = form.nexmoDID.data
        route.apiServer = form.apiServer.data
        db.session.commit()
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.storeID.data = route.storeID
        form.nexmoDID.data = route.nexmoDID
        form.apiServer.data = route.apiServer
    return render_template('route.html', form=form, info="Update Route")


@app.route('/route/<int:route_id>/delete', methods=['POST'])
def delete_route(route_id):
    route = Route.query.get(route_id)
    db.session.delete(route)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
