import requests
from flask import Blueprint, current_app

from api.errors import (UnexpectedPulsediveError,
                        StandardHttpError)
from api.utils import jsonify_data, get_jwt, ssl_error_handler

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
@ssl_error_handler
def health():
    params = {'iid': 2, 'key': get_jwt().get('key')}

    url = current_app.config["API_URL"]

    response = requests.get(url, params)

    error = response.json().get('error')
    if error not in (None, "Indicator not found."):
        raise UnexpectedPulsediveError(error)

    if not response.ok:
        raise StandardHttpError(response)

    return jsonify_data({'status': 'ok'})
