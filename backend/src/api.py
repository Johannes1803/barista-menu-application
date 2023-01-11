import typing

from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink, db
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

"""
@TODO uncomment the following line to initialize the database
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this function will add one
"""
db_drop_and_create_all()

# ROUTES


@app.route("/drinks")
def get_drinks() -> typing.Tuple[typing.Any, int]:
    """
    Get all drinks in database.

    :return: Tuple of json response object, status code
    """
    all_drinks = Drink.query.all()
    all_drinks_short = [drink.short() for drink in all_drinks]

    return jsonify({"success": True, "drinks": all_drinks_short}), 200


@app.route("/drinks-detail")
@requires_auth("get:drinks-detail")
def get_drinks_detail() -> typing.Tuple[typing.Any, int]:
    """Get all the drinks in the database with detailed information.

    :return: Tuple of json response object, status code
    """
    all_drinks = Drink.query.all()
    all_drinks_detailed = [drink.long() for drink in all_drinks]

    return jsonify({"success": True, "drinks": all_drinks_detailed}), 200


@app.route("/drinks", methods=["POST"])
@requires_auth("post:drinks")
def add_new_drink() -> typing.Tuple[typing.Any, int]:
    with app.app_context():
        # try creating a drink instance from the request body
        try:
            app.logger.debug(json.dumps(request.json["recipe"]))
            app.logger.debug(type(json.dumps(request.json["recipe"])))

            drink = Drink(
                title=request.json["title"], recipe=json.dumps(request.json["recipe"])
            )
        except KeyError as e:
            app.logger.warning(e)
            abort(422)
        else:
            # try inserting into db
            try:
                drink.insert()
            except Exception as e:
                app.logger.warning(e)
                abort(500)
            else:
                return jsonify({"success": True, "drinks": [drink.long()]}), 200


@app.route("/drinks/<int:drink_id>", methods=["PATCH"])
@requires_auth("patch:drinks")
def update_drink(drink_id: int) -> typing.Tuple[typing.Any, int]:
    """
    Update a drink object by using PATCH method.

    Return json object: '{"success": True, "drinks": [drink]}', where drink is the patched drink
        and status code.

    :param drink_id: unique identifier of drink instance in db
    :return: Tuple of json response object, status code
    """
    drink_attributes = {column.name for column in Drink.__table__.columns}
    attributes_in_request = set(request.json.keys())
    app.logger.debug(f"attributes in request: {attributes_in_request}")
    app.logger.debug(f"drink_attributes: {drink_attributes}")
    attributes_to_be_patched = drink_attributes & attributes_in_request

    if not attributes_to_be_patched:
        abort(422)
    # try patching attributes of drink (exactly one match expected)
    try:
        n_matches = Drink.query.filter(Drink.id == drink_id).update(
            {
                attr_to_be_patched: request.json[attr_to_be_patched]
                for attr_to_be_patched in attributes_to_be_patched
            }
        )
        db.session.commit()
    except exc.IntegrityError as e:
        app.logger.warning(e)
        abort(422, e)
    except Exception as e:
        app.logger.warning(e)
        abort(500, e)
    else:
        if n_matches == 0:
            abort(404)
        elif n_matches > 1:
            abort(500, "Unique Id constraint violated in db.")
        else:
            drink = Drink.query.get(drink_id)
            return jsonify({"success": True, "drinks": [drink.long()]}), 200


@app.route("/drinks/<int:drink_id>", methods=["DELETE"])
@requires_auth("delete:drinks")
def delete_drink(drink_id: int):
    """
    Delete a drink identified by its id.

    :param drink_id: unique identifier of drink
    :return: Return json {"success": True, "delete": id} where id is the id of the deleted record and status code 200
    :raise 404 error if drink with <id> is not found
    """
    drink = Drink.query.get(drink_id)
    if not drink:
        abort(404)
    try:
        app.logger.debug(drink)
        drink.delete()
    except Exception as e:
        app.logger.debug(e)
        abort(500)
    else:
        return jsonify({"success": True, "id": drink_id}), 200


# Error Handling
@app.errorhandler(422)
def unprocessable(error=None, default_error_msg="unprocessable"):
    try:
        error_msg = error.error
    except (AttributeError, KeyError):
        error_msg = default_error_msg
    return jsonify({"success": False, "error": 422, "message": error_msg}), 422


@app.errorhandler(404)
def resource_not_found(error=None, default_error_msg="Resource not found"):
    try:
        error_msg = error.error
    except (AttributeError, KeyError):
        error_msg = default_error_msg
    return jsonify({"success": False, "error": 404, "message": error_msg}), 404


@app.errorhandler(500)
def internal_server_error(error=None, default_error_msg="Internal server error"):
    try:
        error_msg = error.error
    except (AttributeError, KeyError):
        error_msg = default_error_msg
    return jsonify({"success": False, "error": 500, "message": error_msg}), 500


@app.errorhandler(AuthError)
def auth_error(error: AuthError):
    """
    Handle 401 not authenticated or 403 not authorized errors.

    :param error: Instance of AuthError
    :return: json failure response, status code
    """
    return (
        jsonify({"success": False, "error": error.status_code, "message": error.error}),
        error.status_code,
    )
