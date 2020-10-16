from flask import Blueprint

from api.utils import jsonify_data, get_jwt, ssl_error_handler, perform_request

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
@ssl_error_handler
def health():
    params = {'iid': 2, 'key': get_jwt()}

    _ = perform_request(params)

    return jsonify_data({'status': 'ok'})
