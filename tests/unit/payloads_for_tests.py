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


EXPECTED_PAYLOAD_OBSERVE = {
  "data": {
    "verdicts": {
      "count": 1,
      "docs": [
        {
          "disposition": 5,
          "disposition_name": "Unknown",
          "observable": {
            "type": "domain",
            "value": "cisco.com"
          },
          "type": "verdict",
          "valid_time": {
            "end_time": "2020-02-16T09:53:53Z",
            "start_time": "2019-11-13T03:36:17Z"
          }
        }
      ]
    }
  }
}

PULSEDIVE_REQUEST_TIMOUT = {
  "error": "Request(s) still processing.",
  "status": "processing",
  "note": "status field is in beta: processing | not found | do...",
  "qid": "110740426"
}

PULSEDIVE_RESPONSE_MOCK = {
    "iid": 3658835,
    "type": "domain",
    "indicator": "cisco.com",
    "risk": "none",
    "risk_recommended": "none",
    "manualrisk": 0,
    "retired": "No recent activity",
    "stamp_added": "2018-12-01 16:33:36",
    "stamp_updated": "2020-03-23 19:03:34",
    "stamp_seen": "2019-11-13 03:36:17",
    "stamp_probed": "2019-10-10 17:31:12",
    "stamp_retired": "2020-02-16 09:53:53",
    "recent": 0,
    "riskfactors": [
        {
            "rfid": 58,
            "description": "top 100k domain",
            "risk": "none"
        },
        {
            "rfid": 57,
            "description": "top 10k domain",
            "risk": "none"
        },
        {
            "rfid": 59,
            "description": "top 1k domain",
            "risk": "none"
        }
    ],
    "attributes": {
        "port": [
            "443",
            "80"
        ],
        "protocol": [
            "HTTP",
            "HTTPS"
        ],
        "technology": [
            "Google Analytics"
        ]
    },
    "properties": {
        "cookies": {
            "_fbp": "fb.1.1570728665676.877204079",
            "_ga": "GA1.2.796428004.1570728666",
            "_gcl_au": "1.1.1188910973.1570728665",
            "_gid": "GA1.2.1408301629.1570728666",
        },
        "dns": {
            "A": "72.163.4.185",
            "AAAA": "2001:420:1101:1::185",
            "MNAME": "ns1.cisco.com",
            "MX": [
                "rcdn-mx-01.cisco.com",
                "alln-mx-01.cisco.com",
                "aer-mx-01.cisco.com"
            ],
            "NS": [
                "ns2.cisco.com",
                "ns1.cisco.com",
                "ns3.cisco.com"
            ],
            "RNAME": "postmaster@cisco.com",
            "TXT": [
                "926723159-3188410",
                "v=spf1 redirect=spfa._spf.cisco.com",
                "docusign=5e18de8e-36d0-4a8e-8e88-b7803423fa2f",
                "facebook-domain-verification=qr2nigspzrpa96j1nd9criovuuwino",
                "MS=ms35724259",
                "docusign=95052c5f-a421-4594-9227-02ad2d86dfbe"
            ]
        },
        "geo": {
            "city": "San Jose",
            "country": "United States of America",
            "countrycode": "US",
            "region": "CA"
        },
    },
    "umbrella_rank": 784,
    "umbrella_domain": "cisco.com"
}
