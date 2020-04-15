from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_refer_observables


def test_positive_refer_observable(module_headers):
    """Perform testing for enrich refer observables endpoint to get
    data for observable from Pulsedive

    ID: CCTRI-1007-e6401994-dbef-4467-9792-72f80fd2faa1

    Steps:
        1. Send request to enrich refer observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected refer field for
            observable from Pulsedive

    Importance: Critical
    """
    observable_type = 'ip'
    observable_value = '1.1.1.1'
    observables = [{'type': observable_type, 'value': observable_value}]

    response = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']

    refer = get_observables(response, 'Pulsedive')

    assert refer['id'] == (
        f'ref-pulsedive-search-{observable_type}-{observable_value}')
    assert refer['module'] == 'Pulsedive'
    assert refer['title'] == 'Search for this IP'
    assert refer['description'] == 'Lookup this IP on Pulsedive'
    assert refer['categories'] == ['Pulsedive', 'Search']
    assert refer['url'].startswith('https://pulsedive.com/browse')
