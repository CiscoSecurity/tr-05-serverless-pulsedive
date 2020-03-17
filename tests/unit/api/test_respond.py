from http import HTTPStatus

from pytest import fixture


def routes():
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def expected_payload(route):
    if route.endswith('/observables'):
        return {'data': []}

    if route.endswith('/trigger'):
        return {'data': {'status': 'failure'}}


def test_respond_call_success(route, client, expected_payload):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
