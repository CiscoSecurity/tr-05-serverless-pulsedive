from http import HTTPStatus

from pytest import fixture

from .utils import headers
from tests.unit.payloads_for_tests import EXPECTED_PAYLOAD_INVALID_INPUT


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


def test_enrich_call_without_jwt_success(route, client, valid_json):
    response = client.post(route, json=valid_json)
    assert response.status_code == HTTPStatus.OK


def test_enrich_call_without_jwt_but_invalid_json_failure(route,
                                                          client,
                                                          invalid_json):
    response = client.post(route, json=invalid_json)
    assert response.get_json() == EXPECTED_PAYLOAD_INVALID_INPUT


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(route,
                                                             client,
                                                             valid_jwt,
                                                             invalid_json):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)
    assert response.get_json() == EXPECTED_PAYLOAD_INVALID_INPUT


def test_enrich_call_success(route, client, valid_jwt, valid_json):
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
