from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify

from api.errors import JwtError, InvalidInputError


def url_for(query, key):
    return current_app.config["API_URL"].format(
        query=query,
        key=key
    )


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except KeyError:
        return {'key': ''}
    except (ValueError, AssertionError, JoseError):
        raise JwtError('Invalid Authorization Bearer JWT.')


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.
    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidInputError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    return jsonify({'errors': [error]})
