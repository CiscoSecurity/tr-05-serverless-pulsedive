from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g

from api.errors import JwtError, InvalidInputError, PulsediveKeyError


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


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_result():
    result = {'data': {}}

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)
    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)
    if g.get('judgements'):
        result['data']['judgements'] = format_docs(g.judgements)
    if g.get('verdicts'):
        result['data']['verdicts'] = format_docs(g.verdicts)
    if g.get('relationships'):
        result['data']['relationships'] = format_docs(g.relationships)

    if not result['data']:
        del result['data']

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def key_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except KeyError:
            raise PulsediveKeyError
        return result
    return wrapper
