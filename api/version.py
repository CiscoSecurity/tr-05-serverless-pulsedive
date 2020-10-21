from flask import Blueprint, current_app

version_api = Blueprint('version', __name__)


@version_api.route('/version', methods=['POST'])
def version():
    return {'version': current_app.config['VERSION']}
