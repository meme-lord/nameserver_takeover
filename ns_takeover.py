import sys

from dns_util import enumerate_nameservers
from usage import parse_args
from utils import (
    clear_global_state,
    set_global_state_with_args,
    get_available_base_domains,
    get_nameservers_with_no_ip
)
import global_state
from sys import stderr


def output_info(target_hostname):
    """
    Iterates through MASTER_DNS_CACHE, and calls _get_graph_data_for_ns_result()
    """
    print(f'[ STATUS ] Results from {target_hostname}', file=stderr)

    # Make all nameservers which were specified with an AA flag blue
    for ns_hostname in global_state.AUTHORITATIVE_NS_LIST:
        print(f'[ Authoritative NS ] {ns_hostname}', file=stderr)

    # Make all nameservers without any IPs red because they are probably vulnerable
    for ns_hostname in get_nameservers_with_no_ip():
        print(f'[No IP] {ns_hostname}')

    # Make all nameservers with available base domains orange because they are probably vulnerable
    for base_domain, ns_hostname in get_available_base_domains():
        print(f'[Unregistered] Base domain {base_domain} unregistered for {ns_hostname}')

    # Make nodes for DNS error states encountered like NXDOMAIN, Timeout, etc.
    for query_error in global_state.QUERY_ERROR_LIST:
        print(f'[ ERROR ] {query_error["ns_hostname"]} -> {query_error["error"]}')


def main(command_line_args=sys.argv[1:]):
    args = parse_args(command_line_args)
    set_global_state_with_args(args)

    if args.target_hostname:
        target_hostnames = [args.target_hostname]
    else:
        with open(args.target_hostnames_list) as targets:
            target_hostnames = targets.read().splitlines()

    for target_hostname in target_hostnames:
        clear_global_state()
        enumerate_nameservers(target_hostname)
        output_info(target_hostname)

    return 0


if __name__ == '__main__':
    sys.exit(main())
