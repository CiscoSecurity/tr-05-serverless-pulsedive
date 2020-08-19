import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition',
    (('13.79.174.77', 'ip', 'Clean', 1),
     ('yizaiwl.cc', 'domain', 'Malicious', 2),
     ('208.91.197.91', 'ip', 'Suspicious', 3),
     ('5.79.66.145', 'ip', 'Unknown', 5))
)
def test_positive_verdict(module_headers, observable, observable_type,
                          disposition_name, disposition):
    """Perform testing for enrich observe observables endpoint to get
    verdicts for observable from Pulsedive

    ID: CCTRI-817-d09f2644-567e-479c-a57c-142a68204acf

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdicts for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']

    response_from_pulsedive = get_observables(response_from_all_modules,
                                              MODULE_NAME)

    assert response_from_pulsedive['module']
    assert response_from_pulsedive['module_instance_id']
    assert response_from_pulsedive['module_type_id']

    verdicts = response_from_pulsedive['data']['verdicts']
    assert verdicts['count'] == 1

    assert verdicts['docs'][0]['type'] == 'verdict'
    assert verdicts['docs'][0]['disposition'] == disposition
    assert verdicts['docs'][0]['disposition_name'] == disposition_name
    assert verdicts['docs'][0]['observable'] == observables[0]
    assert verdicts['docs'][0]['valid_time']['start_time']
    assert verdicts['docs'][0]['valid_time']['end_time']
