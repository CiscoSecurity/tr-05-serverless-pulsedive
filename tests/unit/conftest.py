from datetime import datetime

import jwt
from pytest import fixture
from unittest.mock import MagicMock
from tests.unit.payloads_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT, PRIVATE_KEY
)

from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    payload = {
        'key': 'my_key_for_pulsedive',
        'jwks_host': 'visibility.amp.cisco.com',
        'aud': 'http://localhost'
    }
    return jwt.encode(
        payload, client.application.rsa_private_key, algorithm='RS256',
        headers={
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7'
        }
    )


@fixture(scope='session')
def valid_jwt_with_limit_1(client):
    payload = {
        'key': 'my_key_for_pulsedive',
        'jwks_host': 'visibility.amp.cisco.com',
        'aud': 'http://localhost',
        'CTR_ENTITIES_LIMIT': 1
    }
    return jwt.encode(
        payload, client.application.rsa_private_key, algorithm='RS256',
        headers={
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7'
        }
    )


@fixture(scope='session')
def invalid_jwt(valid_jwt, client):
    payload = jwt.decode(valid_jwt, options={'verify_signature': False})

    # Corrupt the valid JWT by tampering with its payload.
    del payload['key']

    payload = jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7'
            }
        )

    return payload


@fixture(scope='session')
def get_pub_key():
    mock_response = MagicMock()
    payload = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='module')
def expected_payload_unsupported_type(route):
    payload_to_route_match = {
        '/deliberate/observables': {},
        '/refer/observables': {'data': []},
        '/observe/observables': {'data': {}}
    }
    return payload_to_route_match[route]
