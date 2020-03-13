EXPECTED_PAYLOAD_FORBIDDEN = {
        "errors": [
            {
                "code": "forbidden",
                "message": "Invalid Authorization Bearer JWT.",
                "type": "fatal",
            }
        ]
    }

EXPECTED_PAYLOAD_REQUEST_TIMOUT = {
        "errors": [
            {
                "code": "request timeout",
                "message": "Request(s) still processing.",
                "type": "fatal",
            }
        ]
    }
