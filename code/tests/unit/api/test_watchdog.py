from http import HTTPStatus

from pytest import fixture


def routes():
    yield '/watchdog'


@fixture(scope='module', params=routes(), ids=lambda route: f'GET {route}')
def route(request):
    return request.param


@fixture(scope='module')
def expected_payload(client):
    return {'data': 'test'}


def test_version_call_success(route, client, expected_payload):
    response = client.get(route, headers={'Health-Check': 'test'})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
