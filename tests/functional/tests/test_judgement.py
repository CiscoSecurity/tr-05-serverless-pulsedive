import pytest

from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition,severity',
    (('185.141.25.242', 'ip', 'Clean', 1, 'None'),
     ('yizaiwl.cc', 'domain', 'Malicious', 2, 'High'),
     ('208.91.197.91', 'ip', 'Suspicious', 3, 'Low'),
     ('https://www.google.com/', 'url', 'Unknown', 5, 'Unknown'))
)
def test_positive_judgement(module_headers, observable, observable_type,
                            disposition_name, disposition, severity):
    """Perform testing for enrich observe observables endpoint to get
    judgements for observable from Pulsedive

    ID: CCTRI-908-94c4caa9-12c6-43cb-9777-cc6c9dcd289b

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected judgements for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    judgements = get_observables(
        response, 'Pulsedive')['data']['judgements']
    assert judgements['count'] == 1

    judgement = judgements['docs'][0]

    assert 'schema_version' in judgement
    assert judgement['type'] == 'judgement'
    assert judgement['source'] == 'Pulsedive'
    assert judgement['disposition'] == disposition
    assert judgement['disposition_name'] == disposition_name
    assert judgement['observable'] == observables[0]
    assert 'start_time' in judgement['valid_time']
    assert 'end_time' in judgement['valid_time']
    assert 'id' in judgement
    assert judgement['source_uri'].startswith(
        'https://pulsedive.com/indicator/?iid=')
    assert judgement['tlp'] == 'white'
    assert judgement['priority'] == 85
    assert judgement['confidence'] == 'Medium'
    assert judgement['severity'] == severity
