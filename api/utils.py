import requests
from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError
from http import HTTPStatus

from api.errors import (
    AuthorizationError,
    InvalidInputError,
    PulsediveKeyError,
    PulsediveSSLError,
    UnexpectedPulsediveError
)


def get_jwt():
    """
    Get Authorization token and validate its signature
    against the application's secret key, .
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }

    token = get_auth_token()
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'])
        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token():
    """
    Parse the incoming request's Authorization header and validate it.
    """

    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


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


def perform_request(params):
    headers = {
        'User-Agent': current_app.config['USER_AGENT']
    }

    url = current_app.config['API_URL']

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == HTTPStatus.OK:
        return response.json()

    elif response.status_code == HTTPStatus.UNAUTHORIZED:
        raise AuthorizationError(response.json().get('error'))

    elif response.status_code in current_app.config['NOT_CRITICAL_ERRORS']:
        return {}
    raise UnexpectedPulsediveError(response)


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

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)


def key_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except KeyError:
            raise PulsediveKeyError
        return result
    return wrapper


def ssl_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise PulsediveSSLError(error)
    return wrapper
