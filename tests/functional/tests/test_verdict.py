import pytest

from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition',
    (('185.141.25.242', 'ip', 'Clean', 1),
     ('yizaiwl.cc', 'domain', 'Malicious', 2),
     ('208.91.197.91', 'ip', 'Suspicious', 3),
     ('5.79.66.145', 'ip', 'Unknown', 5))
)
def test_positive_verdict(module_headers, observable, observable_type,
                          disposition_name, disposition):
    """Perform testing for enrich observe observables endpoint to get
    verdicts for observable from Cybercrime-Tracker

    ID: CCTRI-813-700a7520-6454-485c-8daf-f876c6e57602

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdicts for
            observable from Cybercrime-Tracker

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    verdicts = get_observables(
        response, 'Pulsedive')['data']['verdicts']
    assert verdicts['count'] == 1

    for verdict in verdicts['docs']:
        assert verdict['type'] == 'verdict'
        assert verdict['disposition'] == disposition
        assert verdict['disposition_name'] == disposition_name
        assert verdict['observable'] == observables[0]
        assert 'start_time' in verdict['valid_time']
        assert 'end_time' in verdict['valid_time']
