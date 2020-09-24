import requests
from flask import Blueprint, current_app

from api.errors import UnexpectedPulsediveError
from api.utils import jsonify_data, get_jwt, ssl_error_handler

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
@ssl_error_handler
def health():
    params = {'iid': 2, 'key': get_jwt().get('key')}

    url = current_app.config["API_URL"]

    response = requests.get(url, params)

    if not response.ok:
        raise UnexpectedPulsediveError(response)

    return jsonify_data({'status': 'ok'})
