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
  'errors': [
    {'code': 'invalid argument',
             'message': 'Invalid JSON payload received. {0: {\'type\': ["Must '
                        "be one of: 'amp_computer_guid', "
                        "'certificate_common_name', 'certificate_issuer', "
                        "'certificate_serial', 'cisco_mid', 'device', "
                        "'domain', 'email', 'email_messageid', "
                        "'email_subject', 'file_name', 'file_path', "
                        "'hostname', 'imei', 'imsi', 'ip', 'ipv6', "
                        "'mac_address', 'md5', 'mutex', 'ngfw_id', "
                        "'ngfw_name', 'odns_identity', 'odns_identity_label', "
                        "'orbital_node_id', 'pki_serial', 'process_name', "
                        "'registry_key', 'registry_name', 'registry_path', "
                        "'sha1', 'sha256', 'url', 'user', "
                        '\'user_agent\'."]}}',
             'type': 'fatal'}
  ],
}


EXPECTED_PAYLOAD_OBSERVE = {
  "data": {
    "indicators": {
      "count": 5,
      "docs": [
        {
          "producer": "Pulsedive",
          "schema_version": "1.0.17",
          "short_description": "found in threat feeds",
          "title": "found in threat feeds",
          "tlp": "white",
          "source": "Pulsedive",
          "type": "indicator",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        },
        {
          "producer": "Pulsedive",
          "schema_version": "1.0.17",
          "short_description": "registration recently updated",
          "title": "registration recently updated",
          "tlp": "white",
          "source": "Pulsedive",
          "type": "indicator",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        },
        {
          "producer": "Pulsedive",
          "schema_version": "1.0.17",
          "severity": "Medium",
          "short_description": "Threat: Kraken Botnet",
          "title": "Threat: Kraken Botnet",
          "source_uri": "https://pulsedive.com/threat/?tid=9",
          "tags": [
            "malware"
          ],
          "tlp": "white",
          "source": "Pulsedive",
          "type": "indicator",
          "valid_time": {
            "start_time": "2019-01-01T04:01:30Z"
          }
        },
        {
          "producer": "Pulsedive",
          "source": "Pulsedive",
          "schema_version": "1.0.17",
          "severity": "Medium",
          "short_description": "Threat: JS Crypto Miner",
          "title": "Threat: JS Crypto Miner",
          "source_uri": "https://pulsedive.com/threat/?tid=108",
          "tags": [
            "abuse"
          ],
          "tlp": "white",
          "type": "indicator",
          "valid_time": {
            "start_time": "2018-08-06T03:44:07Z"
          }
        },
        {
          "producer": "BBcan177",
          "source": "Pulsedive",
          "schema_version": "1.0.17",
          "short_description": "Feed: BBcan177 DNSBL",
          "title": "Feed: BBcan177 DNSBL",
          "source_uri": "https://pulsedive.com/feed/?fid=13",
          "tags": [
            "general"
          ],
          "tlp": "white",
          "type": "indicator",
          "valid_time": {
            "start_time": "2020-02-10T07:41:05Z"
          }
        }
      ]
    },
    "judgements": {
      "count": 1,
      "docs": [
        {
          "confidence": "Medium",
          "disposition": 3,
          "disposition_name": "Suspicious",
          "observable": {
            "type": "domain",
            "value": "parkingcrew.net"
          },
          "priority": 85,
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "tlp": "white",
          "type": "judgement",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        }
      ]
    },
    "relationships": {
      "count": 5,
      "docs": [
        {
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        },
        {
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        },
        {
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        },
        {
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        },
        {
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        }
      ]
    },
    "sightings": {
      "count": 6,
      "docs": [
        {
          "confidence": "Medium",
          "count": 1,
          "description": "found in threat feeds",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2020-03-31T14:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          },
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "type": "sighting"
        },
        {
          "confidence": "Medium",
          "count": 1,
          "description": "registration recently updated",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2020-03-31T14:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          },
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "type": "sighting"
        },
        {
          "confidence": "Medium",
          "count": 1,
          "description": "Threat: Kraken Botnet",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2019-01-01T04:01:30Z",
            "start_time": "2019-01-01T04:01:30Z"
          },
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/threat/?tid=9",
          "type": "sighting"
        },
        {
          "confidence": "Medium",
          "count": 1,
          "description": "Threat: JS Crypto Miner",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2018-08-06T03:44:07Z",
            "start_time": "2018-08-06T03:44:07Z"
          },
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/threat/?tid=108",
          "type": "sighting"
        },
        {
          "confidence": "Medium",
          "count": 1,
          "description": "Feed: BBcan177 DNSBL",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2020-02-10T07:41:05Z",
            "start_time": "2020-02-10T07:41:05Z"
          },
          "schema_version": "1.0.17",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/feed/?fid=13",
          "type": "sighting"
        },
        {
          "confidence": "Medium",
          "count": 1,
          "description": "Active DNS",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "end_time": "2020-03-31T14:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          },
          "relations": {
            "Active DNS": [
              {
                "iid": 3,
                "indicator": "187.191.98.202",
                "risk": "low",
                "stamp_linked": "2019-06-22 10:46:47",
                "summary": {
                  "properties": {
                    "geo": {
                      "country": "Brazil",
                      "countrycode": "BR",
                      "org": "Mandic S.A."
                    }
                  }
                },
                "type": "ip"
              }
            ]
          },
          "schema_version": "1.0.17",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "type": "sighting"
        }
      ]
    },
    "verdicts": {
      "count": 1,
      "docs": [
        {
          "disposition": 3,
          "disposition_name": "Suspicious",
          "observable": {
            "type": "domain",
            "value": "parkingcrew.net"
          },
          "type": "verdict",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
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
  "iid": 118,
  "type": "domain",
  "indicator": "parkingcrew.net",
  "risk": "medium",
  "risk_recommended": "medium",
  "manualrisk": 0,
  "retired": "No recent activity",
  "stamp_added": "2017-09-27 18:11:58",
  "stamp_updated": "2020-03-31 15:12:55",
  "stamp_seen": "2020-03-31 14:47:36",
  "stamp_probed": "2020-03-31 14:47:39",
  "stamp_retired": '',
  "recent": 0,
  "schema": {
    "hosttype": "Host Type",
    "port": "Port",
    "protocol": "Protocol",
    "technology": "Technology"
  },
  "riskfactors": [
    {
      "rfid": 60,
      "description": "found in threat feeds",
      "risk": "medium"
    },
    {
      "rfid": 32,
      "description": "registration recently updated",
      "risk": "medium"
    },
  ],
  "comments": [
    {
      "cid": 132266,
      "uid": 559,
      "username": "3ch0x2",
      "title": "Cyber Investigator",
      "comment": "",
      "stamp_added": "2020-03-15 22:13:06",
      "stamp_updated": "2020-03-31 14:47:36"
    }
  ],
  "attributes": {
    "hosttype": [
      "Name Server"
    ],
    "port": [
      "443",
      "53",
      "80"
    ],
    "protocol": [
      "DNS",
      "HTTP",
      "HTTPS"
    ],
    "technology": [
      "Nginx"
    ]
  },
  "properties": {
    "dns": {
      "A": "185.53.179.29",
      "MNAME": "ns-1403.awsdns-47.org",
      "MX": "62.116.130.8",
      "NS": [
        "ns-1403.awsdns-47.org",
        "ns-2044.awsdns-63.co.uk",
        "ns-252.awsdns-31.com",
        "ns-547.awsdns-04.net"
      ],
      "RNAME": "hostmaster@parkingcrew.com",
      "TXT": "v=spf1 -all"
    },
    "geo": {
      "city": "REDACTED FOR PRIVACY",
      "country": "Germany",
      "countrycode": "DE",
      "region": "DE"
    },
    "http": {
      "++code": "200",
      "++status": "OK",
      "connection": "keep-alive",
      "Content-Encoding": "gzip",
      "Content-Type": "text/html; charset=UTF-8",
      "date": "Tue, 31 Mar 2020 14:43:33 GMT",
      "Server": "nginx",
      "transfer-encoding": "chunked",
      "Vary": "Accept-Encoding",
      "X-Check": "3c12dc4d54f8e22d666785b733b0052100c53444"
    },
    "whois": {
      "++gdpr": "1",
      "++privacy": "1"
    }
  },
  "threats": [
    {
      "tid": 108,
      "name": "JS Crypto Miner",
      "category": "abuse",
      "risk": "unknown",
      "stamp_linked": "2018-08-06 03:44:07"
    },
    {
      "tid": 9,
      "name": "Kraken Botnet",
      "category": "malware",
      "risk": "unknown",
      "stamp_linked": "2019-01-01 04:01:30"
    },
  ],
  "feeds": [
    {
      "fid": 13,
      "name": "BBcan177 DNSBL",
      "category": "general",
      "organization": "BBcan177",
      "pricing": "free",
      "stamp_linked": "2020-02-10 07:41:05"
    }
  ]
}

EXPECTED_PAYLOAD_OBSERVE_WITH_LIMIT = {
  "data": {
    "indicators": {
      "count": 1,
      "docs": [
        {
          "producer": "Pulsedive",
          "schema_version": "1.0.17",
          "short_description": "found in threat feeds",
          "tlp": "white",
          "source": "Pulsedive",
          "type": "indicator",
          "title": "found in threat feeds",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        }
      ]
    },
    "judgements": {
      "count": 1,
      "docs": [
        {
          "confidence": "Medium",
          "disposition": 3,
          "disposition_name": "Suspicious",
          "observable": {
            "type": "domain",
            "value": "parkingcrew.net"
          },
          "priority": 85,
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "tlp": "white",
          "type": "judgement",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        }
      ]
    },
    "relationships": {
      "count": 1,
      "docs": [
        {
          "relationship_type": "sighting-of",
          "schema_version": "1.0.17",
          "tlp": "white",
          "type": "relationship"
        }
      ]
    },
    "sightings": {
      "count": 1,
      "docs": [
        {
          "confidence": "Medium",
          "count": 1,
          "description": "found in threat feeds",
          "observables": [
            {
              "type": "domain",
              "value": "parkingcrew.net"
            }
          ],
          "observed_time": {
            "start_time": "2020-03-31T14:47:36Z",
            "end_time": "2020-03-31T14:47:36Z"
          },
          "schema_version": "1.0.17",
          "severity": "Medium",
          "source": "Pulsedive",
          "source_uri": "https://pulsedive.com/indicator/?iid=118",
          "type": "sighting"
        }
      ]
    },
    "verdicts": {
      "count": 1,
      "docs": [
        {
          "disposition": 3,
          "disposition_name": "Suspicious",
          "observable": {
            "type": "domain",
            "value": "parkingcrew.net"
          },
          "type": "verdict",
          "valid_time": {
            "end_time": "2020-06-30T20:47:36Z",
            "start_time": "2020-03-31T14:47:36Z"
          }
        }
      ]
    }
  }
}

EXPECTED_PAYLOAD_REFER = {
  "data": [
    {
      "categories": [
        "Search",
        "Pulsedive"
      ],
      "description": "Lookup this domain on Pulsedive",
      "id": "ref-pulsedive-search-domain-cisco.com",
      "title": "Search for this domain",
      "url": "https://pulsedive.com/browse/?q=eyJ0e"
             "XBlIjpbImFydGlmYWN0IiwgImRvbWFpbiIsIm"
             "lwIiwiaXB2NiIsInVybCJdLCJyaXNrIjpbInV"
             "ua25vd24iLCJub25lIiwibG93IiwibWVkaXVt"
             "IiwiaGlnaCIsImNyaXRpY2FsIiwicmV0aXJlZ"
             "CJdLCJsYXN0c2VlbiI6WyJhbGwiXSwiaW5kaW"
             "NhdG9yIjpbeyJyYXciOnsidHlwZSI6ImluZGl"
             "jYXRvciIsInZhbHVlIjoiY2lzY28uY29tIn0sI"
             "CJodG1sc2FmZSI6eyJ0eXBlIjoiaW5kaWNhdG9"
             "yIiwidmFsdWUiOiJjaXNjby5jb20ifSwiZXhhY"
             "3QiOnRydWV9XSwiYXR0cmlidXRlIjpbXSwicHJ"
             "vcGVydHkiOltdLCJ0aHJlYXQiOltdLCAiZmVlZ"
             "CI6W119"
    },
    {
      "categories": [
        "Browse",
        "Pulsedive"
      ],
      "description": "Browse this domain on Pulsedive",
      "id": "ref-pulsedive-detail-domain-parkingcrew.net",
      "title": "Browse domain",
      "url": "https://pulsedive.com/indicator/?iid=118"
    }
  ]
}

PULSEDIVE_ACTIVE_DNS_RESPONCE = {
  "Active DNS":
  [
    {
      "iid": 3,
      "indicator": "187.191.98.202",
      "type": "ip",
      "risk": "low",
      "stamp_linked": "2019-06-22 10:46:47",
      "summary": {
        "properties": {
          "geo": {
            "country": "Brazil",
            "org": "Mandic S.A.",
            "countrycode": "BR"
          }
        }
      }
    }
  ]
}

EXPECTED_RESPONSE_KEY_ERROR = {
  "errors": [
    {
      "code": "key error",
      "message": "The data structure of Pulsedive API "
                 "has changed. The module is broken.",
      "type": "fatal"
    }
  ]
}

INVALID_PULSEDIVE_RESPONSE = {
  "iid": 3658835,
  "type": "domain",
  "indicator": "cisco.com",
  "risk_recommended": "none",
  "manualrisk": 0,
  "retired": "No recent activity",
  "stamp_added": "2018-12-01 16:33:36",
  "stamp_updated": "2020-06-29 16:11:16",
  "stamp_seen": "2019-11-13 03:36:17",
  "stamp_probed": "2019-10-10 17:31:12",
  "recent": 0
}
