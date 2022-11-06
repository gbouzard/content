"""
Integration Information:
Contact:
API Documentation:
EchoTrail:
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import inspect
from datetime import datetime
import json
import urllib3
import ast
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class ExecutionProfile:
    def __init__(self, image: str, **kwargs: Any) -> None:
        self.image = image
        self.children = kwargs['children']
        self.network_ports = kwargs['network_ports']
        self.hostname = kwargs['hostname']
        self.parent_image = kwargs['parent_image']
        self.grandparent_image = kwargs['grandparent_image']
        self.hash = kwargs['hash']
        self.parent_hash = kwargs['parent_hash']
        self.commandline = kwargs['commandline']
        self.environment = kwargs['environment']
        self.record_execution = kwargs['record_execution']


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __is_expired_cache_entry(self, **kwargs):
        """
        Assumes client code only calls this function when cache entry exists...
        """
        calling_method = inspect.stack()[1][3]
        cache_hours = demisto.getParam('cache_hours')
        try:
            cache_hours = int(cache_hours)
            if cache_hours <= 0:
                cache_hours = 0
            elif cache_hours > 74:
                cache_hours = 74
        except Exception:
            return_error('Failed to execute command. Error: Hours to Cache in configuration parameters must be an integer.')

        now = datetime.now()
        NUMBER_OF_SECONDS = cache_hours * 3600
        if 'echotrail_searchterm' == calling_method:
            integration_context = get_integration_context()
            integration_context_searchterm_entry = integration_context['searchTerms'][kwargs['search_term']]
            timestamp = datetime.strptime(integration_context_searchterm_entry['timestamp'], DATE_FORMAT)
            if (timestamp - now).total_seconds() > NUMBER_OF_SECONDS:
                #  cache entry is expired, so remove cache entry and return True
                integration_context['searchTerms'].pop(kwargs['search_term'])
                return True
            else:
                return False
        elif 'echotrail_searchterm_field' == calling_method:
            integration_context = get_integration_context()
            integration_context_searchterm_entry = integration_context['fields'][kwargs['search_term']]
            integration_context_searchterm_field_entry = integration_context_searchterm_entry[kwargs['field']]
            timestamp = datetime.strptime(integration_context_searchterm_field_entry['timestamp'], DATE_FORMAT)
            if timestamp and ((timestamp - now).total_seconds() > NUMBER_OF_SECONDS):
                #  remove cache entry
                integration_context['fields'][kwargs['search_term']].pop(kwargs['field'])
                #  remove entire searchTerm key iff it has no remaining '{{field}}' keys
                if len(integration_context['fields'][kwargs['search_term']]) == 0:
                    integration_context['fields'].pop(kwargs['search_term'])
                return True
            else:
                return False

        elif 'echotrail_searchterm_field_subsearch' == calling_method:
            integration_context = get_integration_context()
            integration_context_searchterm_entry = integration_context['subsearches'][kwargs['search_term']]
            integration_context_searchterm_field_entry = integration_context_searchterm_entry[kwargs['field']]
            integration_context_searchterm_field_subsearch_entry = integration_context_searchterm_field_entry[kwargs['subsearch']]
            timestamp = datetime.strptime(integration_context_searchterm_field_subsearch_entry['timestamp'], DATE_FORMAT)
            if timestamp and ((timestamp - now).total_seconds() > NUMBER_OF_SECONDS):
                # remove cache entry
                integration_context['subsearches'][kwargs['search_term']][kwargs['field'].pop(kwargs['subsearch'])]
                # remove entire field key iff it has no remaining '{{subsearch}}' keys
                if len(integration_context['subsearches'][kwargs['search_term']][kwargs['field']]) == 0:
                    integration_context['subsearches'][kwargs['search_term']].pop(kwargs['field'])
                # remove entire searchTerm key iff it has no remaining '{{field}}' keys
                if len(integration_context['subsearches'][kwargs['search_term']]) == 0:
                    integration_context['subsearches'].pop(kwargs['search_term'])
                return True
            else:
                return False
        elif 'echotrail_score' == calling_method:
            integration_context = get_integration_context()
            cache_timestamp = integration_context['scores'][kwargs['score_hash']]['timestamp']
            if cache_timestamp and ((cache_timestamp - now).total_seconds() > NUMBER_OF_SECONDS):
                integration_context['scores'].pop(kwargs['score_hash'])
                return True
            else:
                return False

    def __cache_response(self, **kwargs):
        time = datetime.now()
        if kwargs['cache_type'] == 'searchTerm':
            integration_context_to_set = {"searchTerms": {
                kwargs['search_term']: {
                    "timestamp": time.strftime(DATE_FORMAT),
                    "results": str(kwargs['resp'])
                }
            }}
            # rsort cache
        elif kwargs['cache_type'] == 'fields':
            integration_context_to_set = {"fields": {
                kwargs['search_term']: {
                    str(kwargs['field']): {
                        "timestamp": time.strftime(DATE_FORMAT),
                        "results": str(kwargs['resp'])
                    }
                }
            }}
            # rsort cache
        elif kwargs['cache_type'] == 'subsearches':
            integration_context_to_set = {"subsearches": {
                kwargs['search_term']: {
                    str(kwargs['field']): {
                        kwargs['subsearch']: {
                            "timestamp": time.strftime(DATE_FORMAT),
                            "results": str(kwargs['resp'])
                        }
                    }
                }
            }}
            # rsort cache
        elif kwargs['cache_type'] == 'score':
            integration_context_to_set = {"scores": {
                str(kwargs['ehash']) : {
                    "timestamp": time.strftime(DATE_FORMAT),
                    "results": str(kwargs['resp'])
                }
            }}
            # rsort cache
        set_integration_context(integration_context_to_set)

    """
    def __cache_clean(self, cache_key):
        NUMBER_OF_SECONDS = cache_hours * 3600
        integration_context = get_integration_context()
        now = datetime.now()
        if cache_key == "searchTerms":
            # LIFO, check first cache entry
            integration_context_searchTerms_keys = list(integration_context['searchTerms'].keys())
            oldest_entry = datetime.strptime(integration_context_searchTerms_keys[0]['timestamp'], DATE_FORMAT)
            if (oldest_entry - now).total_seconds() > NUMBER_OF_SECONDS:
                # First cache entry is expired, pop it
                integration_context['searchTerms'].pop(integration_context_searchTerms_keys[0])
                for i in range(1, len(integration_context_searchTerm_keys)):
                    timestamp = x
                    if (timestamp - now).total_seconds() > NUMBER_OF_SECONDS:
                        integration_context['searchTerms']
    """

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API
    def echotrail_searchterm(self, searchTerm):
        """
        Get a  full summary of the requested filename or hash. The summary will contain similar
            information to what can be found in a search on our website.

        Args:
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
        Raises:
            e: _description_
        Returns:
            Description
            EchoTrail Prevalence Score
            Host Prevalence, Execution Rank
            Top 20 Parents
            Top 20 Children
            top 20 Grandparents
            Top 20 hashes/filenames
            Top 20 Paths
            Top 20 Network connection ports
            Intel
        """
        integration_context: Dict = get_integration_context()
        #  Check if cache parameter is enabled and check cache for searchTerm
        if bool(demisto.getParam('cache')) is False:
            response = self._http_request("GET", "v1/private/insights/{}".format(searchTerm))
            return response
        elif ('searchTerms' not in integration_context) or (searchTerm not in integration_context['searchTerms']):
            #  SearchTerm not cached, so get response and cache it
            response = self._http_request("GET", "v1/private/insights/{}".format(searchTerm))
            self.__cache_response(cache_type="searchTerm", search_term=searchTerm, resp=response)
            return response
        else:
            #  SearchTerm is cached
            try:
                #  Check if cached entry is expired
                expired = self.__is_expired_cache_entry(search_term=searchTerm)
                if expired is True:
                    #  Remove expired entry from cache
                    integration_context['searchTerms'].pop(searchTerm)
                    #  Perform new query and cache result
                    response = self._http_request("GET", "v1/private/insights/{}".format(searchTerm))
                    self.__cache_response(cache_type="searchTerm", search_term=searchTerm, resp=response)
                    return response
                else:
                    #  Cached entry is not expired, so use it
                    demisto.log('Using cached entry') #  TODO: remove line in production
                    return ast.literal_eval(integration_context['searchTerms'][searchTerm]['results'])
            except Exception as e:
                demisto.results(str(e))

    def echotrail_searchterm_field(self, searchTerm, field):
        """
        Get one particular field from the summary results. If you only need access to one field in
        the above summary, use this resource as it will be much more efficient to fetch the one
        field you need.

        Args:
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
            field (str): must be one of description, rank, host_prev, eps, parents, children, grandparents,
                hashes, paths, network, intel

        Raises:
            e: _description_
            ValueError: _description_

        Returns:
            str: a field from the summary results
        """
        if field in {'description', 'rank', 'host_prev', 'eps', 'parents', 'children',
                     'grandparents', 'hashes', 'paths', 'network', 'intel'}:
            integration_context: Dict = get_integration_context()
            #  Check if cache parameter is enabled and check cache for field
            if bool(demisto.getParam('cache')) is False:
                response = self._http_request("GET", "v1/private/insights/{}/{}".format(searchTerm, field))
                return response
            elif ('fields' not in integration_context) or \
                (searchTerm not in integration_context['fields']) or \
                (field not in integration_context['fields'][searchTerm]):
                #  Field not cached, so get response and cache it
                response = self._http_request("GET", "v1/private/insights/{}/{}".format(searchTerm, field))
                self.__cache_response(cache_type="fields", search_term=searchTerm, field=field, resp=response)
                return response
            else:
                #  Field is cached
                try:
                    #  Check if cached entry is expired
                    expired = self.__is_expired_cache_entry(search_term=searchTerm, field=field)
                    if expired is True:
                        #  Remove expired entry from cache
                        integration_context['fields'][searchTerm].pop(field)
                        if len(integration_context['fields'][searchTerm]) == 0:
                            integration_context['fields'].pop(searchTerm)
                    else:
                        #  Cached entry is not expired, so use it
                        demisto.log('Using cached entry') #  TODO: remove line in production
                        return ast.literal_eval(integration_context['fields'][searchTerm][field]['results'])
                except Exception as e:
                    demisto.results(str(e))
        else:
            return "Invalid Field"

    def echotrail_searchterm_field_subsearch(self, searchTerm, field, subsearch):
        """For fields with a list of results, such as parents, this resource gives you the ability \
        to subsearch that list. Subsearch can be any string to search for within the results of \
        the field search. For example, when subsearching a list of parents, the subsearch string \
        should be a filename with extension.

        Args:
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
            field (str): must be one of description, rank, host_prev, eps, parents, children, grandparents,
                \ hashes, paths, network, intel
            subsearch (str): A substring to search for

        Raises:
            e: _description_
            ValueError: _description_

        Returns:
            str: Value cooresponding to the key provided as subsearch
        """
        if field in ['parents', 'children', 'grandparents', 'hashes', 'paths']:
            integration_context: Dict = get_integration_context()
            #  Check if cache parameter is disabled
            if (bool(demisto.getParam('cache')) is False):
                response = self._http_request("GET", "v1/private/insights/{}/{}/{}".format(searchTerm, field, subsearch))
                return response
            else:
                # Cache parameter is enabled, now check if cach entry exists
                if ('subsearches' not in integration_context) or \
                (searchTerm not in integration_context['subsearches']) or \
                (field not in integration_context['subsearches'][searchTerm]) or \
                (subsearch not in integration_context['subsearches'][searchTerm][field]):
                    #  Subsearch is not cached, get response and cache it
                    response = self._http_request("GET", "v1/private/insights/{}/{}/{}".format(searchTerm, field, subsearch))
                    self.__cache_response(cache_type="subsearches", search_term=searchTerm, field=field, subsearch=subsearch, resp=response)
                    return response
                else:
                    #  Field is cached
                    try:
                        #  Check if cached entry is expired
                        # HERE
                        expired = self.__is_expired_cache_entry(search_term=searchTerm, field=field, subsearch=subsearch)
                        if expired is True:
                            #  Remove expired entry from cache
                            integration_context['subsearches'][searchTerm].pop(field)
                            if len(integration_context['subsearches'][searchTerm]) == 0:
                                integration_context['subsearches'].pop(searchTerm)
                        else:
                            #  Cached entry is not expired, so use it
                            demisto.log("Using cached entry") #  TODO: remove in production

                            return ast.literal_eval(integration_context['subsearches'][searchTerm][field][subsearch]['results'])
                    except Exception as e:
                        demisto.results(str(e))
        else:
            return "Invalid Field"

    def echotrail_score(self, image='', hostname='', parent_image='', grandparent_image='', ehash='', parent_hash='',
                        commandline='', children=None, network_ports=None, environment='', record_execution=''):
        """Scores will be broken down into 4 categories, host, environment, customer and global, when
        enough information is provided to calculate a score for each category. If an environment name
        is not provided, the default environment will be used, and an environment score will not be
        provided. Also, when individual fields, like grandparent, for example, are not provided, those
        fields will be excluded from the scoring process and the scores will be dynamically adjusted to
        account for only the fields provided.

        Args:
            image (str): Image is the only required field. Ideally it should contain a full path and executable name.
            hostname (str): If a hostname is provided, host-level scores will also be calculated
            parent_image (str): The parent path and executable name obvserved.
            grandparent_image (str): The grandparent path and executable name observed.
            hash (str): The SHA256 hash observed.
            parent_hash (str): The SHA256 hash of the parent.
            commandline (str): The commandline observed. Commandline scoring will be coming soon.
            children (arr): Any children observed.
            network_ports (arr): Any network connection ports observed.
            environment (str): This field allows for segregation of statistics for different environments. It can be used for
                different network segments or customers. It is up to the user to determine if and how this field is used.
            record_execution (bool): This field defaults to false as we don’t want to record a query as an actual real-world
                execution unless you specify that we should do so. Set this field to true for us to record the execution
                statistics.
        """
        try:
            payload = {
                "image": image,
                "hostname": hostname,
                "parent_image": parent_image,
                "grandparent_image": grandparent_image,
                "hash": ehash,
                "parent_hash": parent_hash,
                "commandline": commandline,
                "children": children,
                "network_ports": network_ports,
                "environment": environment,
                "record_execution": False
            }

            integration_context: Dict = get_integration_context()
            #  Check if cache parameter is disabled
            if (bool(demisto.getParam('cache')) is False):
                if children is None:
                    children = []
                if network_ports is None:
                    network_ports = []

                response = self._http_request(method="POST", url_suffix="score", data=json.dumps(payload))
                return response
            else:
                hash_list = image + str(hostname) + str(parent_image) + str(grandparent_image) + str(ehash) + str(parent_hash) + str(commandline) + str(children) + str(network_ports) + str(environment) + str(record_execution)
                ehash=str(hash(str(hash_list)))
                if ('scores' not in integration_context):
                    #  No score cached, get response and cache it
                    if children is None:
                        children = []
                    if network_ports is None:
                        network_ports = []

                    response = self._http_request(method="POST", url_suffix="score", data=json.dumps(payload))
                    self.__cache_response(cache_type="score", ehash=ehash, resp=response)
                    return response
                else:
                    #  Score might be cached
                    try:
                        #  Check if cached entry is expired, cleaning up other expried cached entries as we go
                        scoreKeys = integration_context['scores'].keys()
                        cached = False
                        cached_request_hash = ''
                        for s in scoreKeys:
                            if s == ehash:
                                # return cached entry
                                demisto.log('Using cached entry') #  TODO: remove in production
                                cached = True
                                cached_request_hash = s
                                break
                            else:
                                print(s + ":" + ehash)
                        if cached is True:
                            expired = self.__is_expired_cache_entry(score_hash=cached_request_hash)
                            if expired is True:
                                #  Remove expired entry from cache
                                integration_context['scores'].pop(cached_request_hash)
                            else:
                                demisto.log('Using cached entry')
                                return ast.literal_eval(integration_context['scores'][ehash]['results'])
                            #  Cached entry is not expired, so use it
                        else:
                            response = self._http_request(method="POST", url_suffix="score", data=json.dumps(payload))
                            self.__cache_response(cache_type="score", ehash=ehash, resp=response)
                            return response
                    except Exception as e:
                        demisto.results(str(e))
        except Exception as e:
            return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


''' HELPER FUNCTIONS '''


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        response = client.echotrail_searchterm("cmd.exe")['description']
        message = str(response)
        if 'The Windows Command Prompt' in response:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = 'Could not connect to server'
    return message


def echotrail_searchterm_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = str(args['searchTerm'])
    searchTermPrefix = searchTerm.replace('.', '_')
    result = client.echotrail_searchterm(searchTerm)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm.' + searchTermPrefix,
        outputs_key_field=searchTerm,
        outputs=result,
        raw_response=json.dumps(result),
        ignore_auto_extract=True
    )


def echotrail_searchterm_field_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = str(args['searchTerm'])
    searchTermPrefix = searchTerm.replace('.', '_')
    field = str(args['field'])
    #  fieldPrefix = field.replace('.', '_')
    result = client.echotrail_searchterm_field(searchTerm, field)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm.' + searchTermPrefix + '.Field',
        outputs_key_field=searchTerm,
        outputs=result,
        raw_response=json.dumps(result),
        ignore_auto_extract=True
    )


def echotrail_searchterm_field_subsearch_command(client: Client, args: Dict[str, Any]):
    searchTerm = str(args['searchTerm'])
    searchTermPrefix = searchTerm.replace('.', '_')
    field = str(args['field'])
    fieldPrefix = field.replace('.', '_')
    subsearch = str(args['subsearch'])
    subsearchPrefix = str(args['subsearch']).replace('.', '_')
    #  subsearchPrefix = subsearch.replace('.', '_')

    if (type(searchTerm) != str or type(field) != str or type(subsearch) != str):
        return_error(f"Failed to execute {'echotrail_searchterm_field_subsearch_command'} command. \
                Error: ['searchTerm', 'field', 'subsearch'] must be of type (str)")

    else:
        result = client.echotrail_searchterm_field_subsearch(searchTerm, field, subsearch)
        readable_out = ""
        if isinstance(result, list):
            searchTerm = result[0]
            prevelance = result[1]
            subsearch_result = [
                {
                    "SearchTerm": searchTerm,
                    "Prevelance": prevelance
                }
            ]
            markdown = '### EchoTrail\n'
            markdown += tableToMarkdown('SubSearch Results', subsearch_result, headers=['SearchTerm', 'Prevelance'])
            readable_out += markdown
        else:
            readable_out += "No results found."

        return CommandResults(
            outputs_prefix='EchoTrail.SearchTerm.' + searchTermPrefix + '.Field.' + fieldPrefix + '.SubSearch.' + subsearchPrefix,
            outputs_key_field=searchTerm,
            readable_output=readable_out,
            outputs=result,
            raw_response=json.dumps(result),
            ignore_auto_extract=True
        )


def echotrail_score_command(client: Client, execution_profile: ExecutionProfile) -> CommandResults:
    hostname = execution_profile.hostname
    image = execution_profile.image
    parent_image = execution_profile.parent_image
    grandparent_image = execution_profile.grandparent_image
    hash = execution_profile.hash  # type: str
    parent_hash = execution_profile.parent_hash
    commandline = execution_profile.commandline
    children = execution_profile.children
    network_ports = execution_profile.network_ports
    environment = execution_profile.environment
    record_execution = execution_profile.record_execution

    try:
        result = client.echotrail_score(image, hostname, parent_image, grandparent_image, hash, parent_hash, commandline,
                                        children, network_ports, environment, record_execution)
        return CommandResults(
            outputs_prefix='EchoTrail.Score',
            outputs_key_field='' + image,
            outputs=result,
            raw_response=json.dumps(result),
            ignore_auto_extract=True
        )
    except Exception as e:
        demisto.error("Failed to execute 'echotrail_score_command' command. Error: {}", {str(e)})
        return CommandResults(
            outputs_prefix=None,
            outputs=result,
        )


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    api_key = demisto.getParam('api_key').get('password')
    args = demisto.args()
    command = demisto.command()
    base_url = 'https://api.echotrail.io/'
    verify_certificate = not argToBoolean(demisto.getParam('insecure'))
    proxy = not argToBoolean(demisto.getParam('proxy'))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        # headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'X-Api-key': api_key},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)  # type: Optional[Any]
            demisto.results(result)
        elif command == 'echotrail-searchterm':
            result = echotrail_searchterm_command(client, args)
        elif command == 'echotrail-searchterm-field':
            result = echotrail_searchterm_field_command(client, args)
        elif command == 'echotrail-searchterm-field-subsearch':
            result = echotrail_searchterm_field_subsearch_command(client, args)
        elif command == 'echotrail-score':
            executionProfile = ExecutionProfile(image=args.get('image'),
                                                children=args.get('children'),
                                                network_ports=args.get('network_ports'),
                                                hostname=args.get('hostname'),
                                                parent_image=args.get('parent_image'),
                                                grandparent_image=args.get('grandparent_image'),
                                                ehash=args.get('hash'),
                                                parent_hash=args.get('parent_hash'),
                                                commandline=args.get('commandline'),
                                                environment=args.get('environment'),
                                                record_execution=args.get('record_execution')
                                                )  # type: ExecutionProfile
            result = echotrail_score_command(client, executionProfile)
            #  raise NotImplementedError(f'Command {command} is not implemented')
        # Log exceptions and return errors
        return_results(result)
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
