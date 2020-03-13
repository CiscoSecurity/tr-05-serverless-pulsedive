import requests
from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data, jsonify_errors

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():

    key, error = get_jwt().get('key'), get_jwt().get('error')

    url = f'{current_app.config["API_URL"]}info.php?iid=2'

    if key:
        url += f'&key={key}'
    if error:
        return jsonify_errors('Forbidden', error)

    response = requests.get(url)

    if response.ok:
        error = response.json().get('error')
        if error:
            code = current_app.config['API_ERRORS_STANDARDISATION']\
                .get(error, 'unknown')
            return jsonify_errors(code, error)
        else:
            return jsonify_data({'status': 'ok'})
    else:
        code = response.reason
        message = 'The Pulsedive API error.'
        return jsonify_errors(code, message)
