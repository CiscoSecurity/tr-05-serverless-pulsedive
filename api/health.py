import requests
from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt().get('key')

    url = f'{current_app.config["API_URL"]}info.php?iid=2'

    if key:
        url += f'&key={key}'

    response = requests.get(url)

    if response.ok:
        if response.json().get('error'):
            message = response.json()['error']
            code = current_app.config['API_ERRORS'].get(message, 'unknown')
            return jsonify_errors(code, message)
        else:
            return jsonify_data({'status': 'ok'})
    else:
        code = response.reason
        message = 'The Pulsedive API error.'
        return jsonify_errors(code, message)
