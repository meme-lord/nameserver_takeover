import json
import time
import xmlrpc.client
import boto3
import requests
import global_state

from sys import stderr


DOMAIN_AVAILABILITY_CACHE = {}
gandi_api_v4 = xmlrpc.client.ServerProxy(
    uri='https://rpc.gandi.net/xmlrpc/',
)


def _auto_retry(registar_function):
    """
    :type registar_function: function
    Returns a lowercase availability status when given a domain

    :returns: function
    A wrapped registar_function that retries and returns a bool
    """
    def wrapper_of_registar_function(input_domain):
        for _ in range(10):
            status = registar_function(input_domain)
            if status != 'pending':
                break
            time.sleep(1)

        return status.startswith('available')

    return wrapper_of_registar_function


@_auto_retry
def _can_register_with_gandi_api_v4(input_domain):
    """
    :returns: lowercase string
    availability status returned from the API
    """
    status = gandi_api_v4.domain.available(
        global_state.GANDI_API_V4_KEY,
        [input_domain],
    )[input_domain]
    return status


@_auto_retry
def _can_register_with_gandi_api_v5(input_domain):
    """
    For more information, please see
    https://api.gandi.net/docs/domains/

    :returns: lowercase string
    availability status returned from the API
    """
    response = requests.get(
        url='https://api.gandi.net/v5/domain/check',
        params={
            'name': input_domain,
        },
        headers={
            'Authorization': f'Apikey {global_state.GANDI_API_V5_KEY}',
        },
    )
    assert response.status_code == 200

    # I do not know why Gandi does this
    if 'products' not in response.json():
        return 'not_available'

    assert len(response.json()['products']) == 1

    status = response.json()['products'][0]['status']

    return status


@_auto_retry
def _can_register_with_aws_boto3(input_domain):
    """
    :returns: lowercase string
    availability status returned from the API
    """
    with open(global_state.AWS_CREDS_FILE, 'r') as f:
        creds = json.load(f)
    client = boto3.client(
        'route53domains',
        aws_access_key_id=creds['accessKeyId'],
        aws_secret_access_key=creds['secretAccessKey'],
        region_name='us-east-1',  # Only region available
    )
    status = client.check_domain_availability(
        DomainName=input_domain,
    )['Availability']
    return status.lower()


def is_domain_available(input_domain):
    """
    Called if Gandi API key or AWS credentials file is provided.

    Note that we do not do `lru_cache(maxsize=0)` but instead
    use our own cache. This is because we normalize input when
    removing any trailing '.' characters.

    :returns: bool
    """
    if input_domain.endswith('.'):
        input_domain = input_domain[:-1]

    if input_domain in DOMAIN_AVAILABILITY_CACHE:
        return DOMAIN_AVAILABILITY_CACHE[input_domain]

    print(f'[ STATUS ] Checking if {input_domain} is available...', file=stderr)

    if global_state.GANDI_API_V4_KEY:
        _can_register_function = _can_register_with_gandi_api_v4
    elif global_state.GANDI_API_V5_KEY:
        _can_register_function = _can_register_with_gandi_api_v5
    else:
        _can_register_function = _can_register_with_aws_boto3

    domain_available = _can_register_function(input_domain)
    DOMAIN_AVAILABILITY_CACHE[input_domain] = domain_available

    return domain_available
