import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    SOURCE,
    PULSEDIVE_URL,
    MODULE_NAME
)


@pytest.mark.parametrize(
    'observable,observable_type,disposition_name,disposition',
    (('13.79.174.77', 'ip', 'Clean', 1),
     ('1.0.3.4', 'ip', 'Suspicious', 3),
     ('yizaiwl.cc', 'domain', 'Malicious', 2),
     ('https://www.youtube.com/', 'url', 'Unknown', 5))
)
def test_positive_judgement(module_headers, observable, observable_type,
                            disposition_name, disposition):
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

    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_pulsedive_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive_module['module'] == MODULE_NAME
    assert response_from_pulsedive_module['module_instance_id']
    assert response_from_pulsedive_module['module_type_id']

    judgements = response_from_pulsedive_module['data']['judgements']
    assert judgements['count'] == 1

    judgement = judgements['docs'][0]

    assert judgement['schema_version']
    assert judgement['type'] == 'judgement'
    assert judgement['source'] == SOURCE
    assert judgement['disposition'] == disposition
    assert judgement['disposition_name'] == disposition_name
    assert judgement['observable'] == observables[0]
    assert judgement['valid_time']['start_time']
    assert 'end_time' in judgement['valid_time']
    assert judgement['id'].startswith('transient:judgement-')
    assert judgement['source_uri'].startswith(PULSEDIVE_URL)
    assert judgement['tlp'] == 'white'
    assert judgement['priority'] == 85
    assert judgement['confidence'] == 'Medium'
    assert judgement['severity']
