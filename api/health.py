import requests
from flask import Blueprint

from api.errors import (UnexpectedPulsediveError,
                        StandardHttpError)
from api.utils import url_for, jsonify_data, get_jwt

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt().get('key')

    url = url_for("iid=2", key)

    response = requests.get(url)

    error = response.json().get('error')
    if error not in (None, "Indicator not found."):
        raise UnexpectedPulsediveError(error)

    if not response.ok:
        raise StandardHttpError(response)

    return jsonify_data({'status': 'ok'})
