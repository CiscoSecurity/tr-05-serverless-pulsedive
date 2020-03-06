from http import HTTPStatus
from unittest.mock import MagicMock, patch

from authlib.jose import jwt
from pytest import fixture

from .utils import headers


def routes():
    yield "/health"


@fixture(scope="module", params=routes(), ids=lambda route: f"POST {route}")
def route(request):
    return request.param


def test_health_call_without_jwt_failure(route, client):
    response = client.post(route)
    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.json["message"] == "Invalid Authorization Bearer JWT."


@fixture(scope="function")
def pd_api_request():
    with patch("requests.get") as mock_request:
        yield mock_request


def pd_api_response():
    mock_response = MagicMock()

    mock_response.ok = True

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
    mock_response.json = lambda: payload

    return mock_response


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.FORBIDDEN
<<<<<<< HEAD
    assert response.json["message"] == "Invalid Authorization Bearer JWT."


def test_health_call_success(route, client, pd_api_request, valid_jwt):
    app = client.application

    pd_api_request.return_value = pd_api_response()

    response = client.post(route, headers=headers(valid_jwt))

    key = jwt.decode(valid_jwt, app.config["SECRET_KEY"])["key"]
    expected_url = f'{app.config["API_URL"]}info.php?iid=2&key={key}'

    pd_api_request.assert_called_once_with(expected_url)

    expected_payload = {"data": {"status": "ok"}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
=======


def test_health_call_success(route, client, valid_jwt):
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
>>>>>>> develop
