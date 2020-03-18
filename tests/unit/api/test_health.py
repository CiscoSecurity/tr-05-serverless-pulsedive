from http import HTTPStatus
from unittest.mock import MagicMock, patch

from authlib.jose import jwt
from pytest import fixture

from .utils import headers
from tests.unit.payloads_for_tests import (
    EXPECTED_PAYLOAD_FORBIDDEN,
    EXPECTED_PAYLOAD_REQUEST_TIMOUT
)


def routes():
    yield "/health"


@fixture(scope="module", params=routes(), ids=lambda route: f"POST {route}")
def route(request):
    return request.param


def get_expected_url(client, valid_jwt):
    app = client.application
    url = f'{app.config["API_URL"]}info.php?iid=2'
    if valid_jwt:
        url += f'&key={jwt.decode(valid_jwt, app.config["SECRET_KEY"])["key"]}'
    return url


def test_health_call_without_jwt_success(route, client, pd_api_request):
    pd_api_request.return_value = pd_api_response(ok=True)
    response = client.post(route)

    expected_url = get_expected_url(client, valid_jwt=None)
    pd_api_request.assert_called_once_with(expected_url)

    expected_payload = {"data": {"status": "ok"}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_without_jwt_failure(route, client, pd_api_request):
    pd_api_request.return_value = pd_api_response(ok=False)
    response = client.post(route)

    expected_url = get_expected_url(client, valid_jwt=None)
    pd_api_request.assert_called_once_with(expected_url)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_REQUEST_TIMOUT


@fixture(scope="function")
def pd_api_request():
    with patch("requests.get") as mock_request:
        yield mock_request


def pd_api_response(ok):
    mock_response = MagicMock()

    mock_response.ok = True
    if ok:
        payload = {
            "iid": 19,
            "type": "ip",
            "indicator": "144.76.107.175",
            "risk": "none",
            "risk_recommended": "none",
            "manualrisk": 0,
            "retired": "No recent activity",
            "stamp_added": "2017-09-27 18:11:44",
            "stamp_updated": "2018-03-26 15:44:24",
            "stamp_seen": "2017-09-27 18:11:44",
            "stamp_retired": "2018-03-26 15:44:24",
            "recent": 0,
        }
    else:
        payload = {
            "error": "Request(s) still processing.",
            "status": "processing",
            "note": "status field is in beta: processing | not found | do...",
            "qid": "110740426",
        }

    mock_response.json = lambda: payload
    return mock_response


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.get_json() == EXPECTED_PAYLOAD_FORBIDDEN


def test_health_call_success(route, client, pd_api_request, valid_jwt):
    pd_api_request.return_value = pd_api_response(ok=True)
    response = client.post(route, headers=headers(valid_jwt))

    expected_url = get_expected_url(client, valid_jwt)
    pd_api_request.assert_called_once_with(expected_url)

    expected_payload = {"data": {"status": "ok"}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_failure(route, client, pd_api_request, valid_jwt):
    pd_api_request.return_value = pd_api_response(ok=False)
    response = client.post(route, headers=headers(valid_jwt))

    expected_url = get_expected_url(client, valid_jwt)
    pd_api_request.assert_called_once_with(expected_url)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_REQUEST_TIMOUT
