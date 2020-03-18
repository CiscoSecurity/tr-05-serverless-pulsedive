EXPECTED_PAYLOAD_FORBIDDEN = {
    "errors": [
        {
            "code": "permission denied",
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

EXPECTED_PAYLOAD_INVALID_INPUT = {
    "errors": [
        {
            "code": "invalid argument",
            "message": {
                "0": {
                    "type": [
                        "Must be one of: 'amp_computer_guid', "
                        "'certificate_common_name', "
                        "'certificate_issuer', "
                        "'certificate_serial', 'cisco_mid', "
                        "'device', 'domain', 'email', "
                        "'email_messageid', 'email_subject', "
                        "'file_name', 'file_path', 'hostname', "
                        "'imei', 'imsi', 'ip', 'ipv6', "
                        "'mac_address', 'md5', 'mutex', "
                        "'ngfw_id', 'ngfw_name', "
                        "'odns_identity', "
                        "'odns_identity_label', "
                        "'orbital_node_id', 'pki_serial', "
                        "'process_name', 'registry_key', "
                        "'registry_name', 'registry_path', "
                        "'sha1', 'sha256', 'url', 'user', "
                        "'user_agent'."
                    ],
                    "value": ["Field may not be blank."],
                }
            },
            "type": "fatal",
        }
    ]
}
