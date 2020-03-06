import requests
from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_jwt().get('key')

    if key is None:
        return None

    url = f'{current_app.config["API_URL"]}info.php?iid=2&key={key}'

    response = requests.get(url)

    if response.ok:
        return jsonify_data({'status': 'ok'})
    else:
        error = response.json()['error']
        return jsonify_errors(error)
