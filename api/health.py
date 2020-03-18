import requests
from flask import Blueprint, current_app

from api.errors import (UnexpectedPulsediveError,
                        StandardHttpError)
from api.utils import get_jwt, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt().get('key')

    url = f'{current_app.config["API_URL"]}info.php?iid=2'

    if key:
        url += f'&key={key}'

    response = requests.get(url)

    if response.ok:
        error = response.json().get('error')
        if error:
            raise UnexpectedPulsediveError(error)
        else:
            return jsonify_data({'status': 'ok'})
    else:
        code = response.reason
        raise StandardHttpError(code)
