# -*- coding: utf-8 -*-
import collections
import datetime
import logging
import os
import re
import sys
import time

import dateutil.parser
import pytz
from six import string_types

from elastalert import ElasticSearchClient
from elastalert.auth import Auth
from elasticsearch.exceptions import TransportError

logging.basicConfig()
logging.captureWarnings(True)
elastalert_logger = logging.getLogger('elastalert')


def get_module(module_name):
    """ Loads a module and returns a specific object.
    module_name should 'module.file.object'.
    Returns object or raises EAException on error. """
    sys.path.append(os.getcwd())
    try:
        module_path, module_class = module_name.rsplit('.', 1)
        base_module = __import__(module_path, globals(), locals(), [module_class])
        module = getattr(base_module, module_class)
    except (ImportError, AttributeError, ValueError) as e:
        raise EAException("Could not import module %s: %s" % (module_name, e)).with_traceback(sys.exc_info()[2])
    return module


def new_get_event_ts(ts_field):
    """ Constructs a lambda that may be called to extract the timestamp field
    from a given event.

    :returns: A callable function that takes an event and outputs that event's
    timestamp field.
    """
    return lambda event: lookup_es_key(event[0], ts_field)


def _find_es_dict_by_key(lookup_dict: dict, term: str, string_multi_field_name: str = "keyword") -> tuple[dict, str]:
    """ Performs a divide-and-conquer recursive search to resolve a term string
    string as compatible dictionary key and list index combination.  It attempts
    to resolve the ambiguity for . and "keyword" being either literals or delimiters.

    For example
       'my.dotted.name.a_child_field.somelist[4]'
    may be found as
        lookup_dict['my.dotted.name']['a_child_field']['somelist'][4]
    or found as
        lookup_dict['my']['dotted.name']['a_child_field.somelist'][4]

    1. Prefers longer fieldname matches
    2. No wildcards exist within the provided ES search terms (these are treated as string literals)
    3. Firstly assumes 'keyword' is a fieldname, then assumes 'keyword' is a subfield specifier for a multifield

    """
    subkeys = term.split('.')

    # reverse to match longest fieldnames first
    for i in reversed(range(1, len(subkeys)+1)):
        root = ".".join(subkeys[0:i])

        # Handle array index references
        # Example
        # foo[3]bar[1]baz is recursively checked as
        # _find_es_dict_by_key(lookup_dict['foo'][3], 'bar[1]baz')

        m = re.search(r'(.+?)\[(\d)\](.*)', root)
        value_index = None
        child_components = []
        if m:
            root = m.group(1)
            value_index = int(m.group(2))
            if m.group(3):
                child_components.append(m.group(3))

        if root in lookup_dict:
            child_components.extend(subkeys[i:])

            # Pursue 'keyword' (if present) as a literal required fieldname
            child_components_options = [child_components]
            try:
                # Then pursue 'keyword' (if present) as subfield specifier by ignoring it
                if child_components[-1] == string_multi_field_name:
                    child_components_options.append(child_components[:-1])
            except IndexError:
                pass

            for child_components_option in child_components_options:
                child = ".".join(child_components_option)
                if value_index is not None:
                    if not child:
                        return lookup_dict[root], value_index
                    if isinstance(lookup_dict[root][value_index], dict):
                        try:
                            return _find_es_dict_by_key(lookup_dict[root][value_index], child, string_multi_field_name)
                        except IndexError:
                            return {}, None

                if child and isinstance(lookup_dict[root], dict):
                    return _find_es_dict_by_key(lookup_dict[root], child, string_multi_field_name)
                return lookup_dict, root
    return {}, None


def set_es_key(lookup_dict, term, value):
    """ Looks up the location that the term maps to and sets it to the given value.
    :returns: True if the value was set successfully, False otherwise.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)

    if value_dict is not None:
        value_dict[value_key] = value
        return True

    return False


def lookup_es_key(lookup_dict, term):
    """ Performs iterative dictionary search for the given term.
    :returns: The value identified by term or None if it cannot be found.
    """
    value_dict, value_key = _find_es_dict_by_key(lookup_dict, term)
    return None if value_key is None else value_dict[value_key]


def ts_to_dt(timestamp):
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    dt = dateutil.parser.parse(timestamp)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=pytz.utc)
    return dt


def dt_to_ts(dt):
    if not isinstance(dt, datetime.datetime):
        elastalert_logger.warning('Expected datetime, got %s' % (type(dt)))
        return dt
    ts = dt.isoformat()
    # Round microseconds to milliseconds
    if dt.tzinfo is None:
        # Implicitly convert local times to UTC
        return ts + 'Z'
    # isoformat() uses microsecond accuracy and timezone offsets
    # but we should try to use millisecond accuracy and Z to indicate UTC
    return ts.replace('000+00:00', 'Z').replace('+00:00', 'Z')


def ts_to_dt_with_format(timestamp, ts_format):
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    dt = datetime.datetime.strptime(timestamp, ts_format)
    # Implicitly convert local timestamps to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_ts_with_format(dt, ts_format):
    if not isinstance(dt, datetime.datetime):
        elastalert_logger.warning('Expected datetime, got %s' % (type(dt)))
        return dt
    ts = dt.strftime(ts_format)
    return ts


def ts_now():
    now = datetime.datetime.now(tz=datetime.UTC)
    return now.replace(tzinfo=dateutil.tz.tzutc())


def ts_utc_to_tz(ts, tz_name):
    """Convert utc time to local time."""
    return ts.astimezone(dateutil.tz.gettz(tz_name))


def inc_ts(timestamp, milliseconds=1):
    """Increment a timestamp by milliseconds."""
    dt = ts_to_dt(timestamp)
    dt += datetime.timedelta(milliseconds=milliseconds)
    return dt_to_ts(dt)


def pretty_ts(timestamp, tz=True, ts_format=None):
    """Pretty-format the given timestamp (to be printed or logged hereafter).
    If tz, the timestamp will be converted to local time.
    Format: YYYY-MM-DD HH:MM TZ"""
    dt = timestamp
    if not isinstance(timestamp, datetime.datetime):
        dt = ts_to_dt(timestamp)
    if tz:
        dt = dt.astimezone(dateutil.tz.tzlocal())
    if ts_format is None:
        return dt.strftime('%Y-%m-%d %H:%M %Z')
    else:
        return dt.strftime(ts_format)


def ts_add(ts, td):
    """ Allows a timedelta (td) add operation on a string timestamp (ts) """
    return dt_to_ts(ts_to_dt(ts) + td)


def hashable(obj):
    """ Convert obj to a hashable obj.
    We use the value of some fields from Elasticsearch as keys for dictionaries. This means
    that whatever Elasticsearch returns must be hashable, and it sometimes returns a list or dict."""
    if not obj.__hash__:
        return str(obj)
    return obj


def format_index(index, start, end, add_extra=False):
    """ Takes an index, specified using strftime format, start and end time timestamps,
    and outputs a wildcard based index string to match all possible timestamps. """
    # Convert to UTC
    start -= start.utcoffset()
    end -= end.utcoffset()

    if "%H" in index:
        dt = datetime.timedelta(hours=1)
        end = end.replace(second=0, microsecond=0, minute=0)
    else:
        dt = datetime.timedelta(days=1)
        end = end.replace(second=0, microsecond=0, minute=0, hour=0)
    if add_extra:
        start -= dt
    indices = set()
    indices.add(start.strftime(index))
    while start <= end:
        start += dt
        indices.add(start.strftime(index))

    if add_extra:
        if index in indices:
            raise EAException("You cannot use a static index {} with search_extra_index".format(index))

    return ','.join(indices)


class EAException(Exception):
    pass


def seconds(td):
    return td.seconds + td.days * 24 * 3600


def total_seconds(dt):
    if dt is None:
        return 0
    else:
        return dt.total_seconds()


def dt_to_int(dt):
    dt = dt.replace(tzinfo=datetime.UTC)
    return int(total_seconds((dt - datetime.datetime.fromtimestamp(0, tz=datetime.UTC))) * 1000)


def unixms_to_dt(ts):
    return unix_to_dt(float(ts) / 1000)


def unix_to_dt(ts):
    dt = datetime.datetime.fromtimestamp(float(ts), tz=datetime.UTC)
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    return dt


def dt_to_unix(dt):
    return int(total_seconds(dt - datetime.datetime(1970, 1, 1, tzinfo=dateutil.tz.tzutc())))


def dt_to_unixms(dt):
    return int(dt_to_unix(dt) * 1000)


def cronite_datetime_to_timestamp(self, d):
    """
    Converts a `datetime` object `d` into a UNIX timestamp.
    """
    if d.tzinfo is not None:
        d = d.replace(tzinfo=None) - d.utcoffset()

    return total_seconds((d - datetime.datetime(1970, 1, 1)))


def add_keyword_postfix(field):
    end = '.keyword'
    if not field.endswith(end):
        field += end
    return field


def replace_dots_in_field_names(document):
    """ This method destructively modifies document by replacing any dots in
    field names with an underscore. """
    for key, value in list(document.items()):
        if isinstance(value, dict):
            value = replace_dots_in_field_names(value)
        if isinstance(key, string_types) and key.find('.') != -1:
            del document[key]
            document[key.replace('.', '_')] = value
    return document


def elasticsearch_client(conf):
    """ returns an :class:`ElasticSearchClient` instance configured using an es_conn_config """
    es_conn_conf = build_es_conn_config(conf)
    auth = Auth()
    username = es_conn_conf['es_username']
    password = es_conn_conf['es_password']
    if es_conn_conf['es_bearer'] or es_conn_conf['es_api_key']:
        username = None
        password = None
    es_conn_conf['http_auth'] = auth(host=es_conn_conf['es_host'],
                                     username=username,
                                     password=password,
                                     aws_region=es_conn_conf['aws_region'],
                                     profile_name=es_conn_conf['profile'])
    if es_conn_conf['es_bearer']:
        es_conn_conf['headers'] = {"Authorization": "Bearer " + es_conn_conf['es_bearer']}
    if es_conn_conf['es_api_key']:
        es_conn_conf['headers'] = {"Authorization": "ApiKey " + es_conn_conf['es_api_key']}

    return ElasticSearchClient(es_conn_conf)


def build_es_conn_config(conf):
    """ Given a conf dictionary w/ raw config properties 'use_ssl', 'es_host', 'es_port'
    'es_username' and 'es_password', this will return a new dictionary
    with properly initialized values for 'es_host', 'es_port', 'use_ssl' and 'http_auth' which
    will be a basicauth username:password formatted string """
    parsed_conf = {}
    parsed_conf['use_ssl'] = os.environ.get('ES_USE_SSL', False)
    parsed_conf['verify_certs'] = True
    parsed_conf['ca_certs'] = None
    parsed_conf['client_cert'] = None
    parsed_conf['client_key'] = None
    parsed_conf['http_auth'] = None
    parsed_conf['es_username'] = None
    parsed_conf['es_password'] = None
    parsed_conf['es_api_key'] = None
    parsed_conf['es_bearer'] = None
    parsed_conf['aws_region'] = None
    parsed_conf['profile'] = None
    parsed_conf['headers'] = None
    parsed_conf['es_host'] = os.environ.get('ES_HOST', conf['es_host'])
    parsed_conf['es_port'] = int(os.environ.get('ES_PORT', conf['es_port']))

    es_hosts = os.environ.get('ES_HOSTS')
    es_hosts = parse_hosts(es_hosts, parsed_conf.get('es_port')) if es_hosts else conf.get('es_hosts')
    parsed_conf['es_hosts'] = es_hosts

    parsed_conf['es_url_prefix'] = ''
    parsed_conf['es_conn_timeout'] = conf.get('es_conn_timeout', 20)
    parsed_conf['send_get_body_as'] = conf.get('es_send_get_body_as', 'GET')
    parsed_conf['ssl_show_warn'] = conf.get('ssl_show_warn', True)

    if os.environ.get('ES_USERNAME'):
        parsed_conf['es_username'] = os.environ.get('ES_USERNAME')
        parsed_conf['es_password'] = os.environ.get('ES_PASSWORD')
    elif 'es_username' in conf:
        parsed_conf['es_username'] = conf['es_username']
        parsed_conf['es_password'] = conf['es_password']

    if os.environ.get('ES_API_KEY'):
        parsed_conf['es_api_key'] = os.environ.get('ES_API_KEY')
    elif 'es_api_key' in conf:
        parsed_conf['es_api_key'] = conf['es_api_key']

    if os.environ.get('ES_BEARER'):
        parsed_conf['es_bearer'] = os.environ.get('ES_BEARER')
    elif 'es_bearer' in conf:
        parsed_conf['es_bearer'] = conf['es_bearer']

    if 'aws_region' in conf:
        parsed_conf['aws_region'] = conf['aws_region']

    if 'profile' in conf:
        parsed_conf['profile'] = conf['profile']

    if 'use_ssl' in conf:
        parsed_conf['use_ssl'] = conf['use_ssl']

    if 'verify_certs' in conf:
        parsed_conf['verify_certs'] = conf['verify_certs']

    if 'ca_certs' in conf:
        parsed_conf['ca_certs'] = conf['ca_certs']

    if 'client_cert' in conf:
        parsed_conf['client_cert'] = conf['client_cert']

    if 'client_key' in conf:
        parsed_conf['client_key'] = conf['client_key']

    if 'es_url_prefix' in conf:
        parsed_conf['es_url_prefix'] = conf['es_url_prefix']

    return parsed_conf


def pytzfy(dt):
    # apscheduler requires pytz timezone objects
    # This function will replace a dateutil.tz one with a pytz one
    if dt.tzinfo is not None:
        new_tz = pytz.timezone(dt.tzinfo.tzname('Y is this even required??'))
        return dt.replace(tzinfo=new_tz)
    return dt


def parse_duration(value):
    """Convert ``unit=num`` spec into a ``timedelta`` object."""
    unit, num = value.split('=')
    return datetime.timedelta(**{unit: int(num)})


def parse_deadline(value):
    """Convert ``unit=num`` spec into a ``datetime`` object."""
    duration = parse_duration(value)
    return ts_now() + duration


def flatten_dict(dct, delim='.', prefix=''):
    ret = {}
    for key, val in list(dct.items()):
        if type(val) == dict:
            ret.update(flatten_dict(val, prefix=prefix + key + delim))
        else:
            ret[prefix + key] = val
    return ret


def resolve_string(string, match, missing_text='<MISSING VALUE>'):
    """
        Given a python string that may contain references to fields on the match dictionary,
            the strings are replaced using the corresponding values.
        However, if the referenced field is not found on the dictionary,
            it is replaced by a default string.
        Strings can be formatted using the old-style format ('%(field)s') or
            the new-style format ('{match[field]}').

        :param string: A string that may contain references to values of the 'match' dictionary.
        :param match: A dictionary with the values to replace where referenced by keys in the string.
        :param missing_text: The default text to replace a formatter with if the field doesnt exist.
    """
    flat_match = flatten_dict(match)
    flat_match.update(match)
    dd_match = collections.defaultdict(lambda: missing_text, flat_match)
    dd_match['_missing_value'] = missing_text
    while True:
        try:
            string = string % dd_match
            string = string.format(**dd_match)
            break
        except KeyError as e:
            if '{%s}' % str(e).strip("'") not in string:
                break
            string = string.replace('{%s}' % str(e).strip("'"), '{_missing_value}')

    return string


def should_scrolling_continue(rule_conf):
    """
    Tells about a rule config if it can scroll still or should stop the scrolling.

    :param: rule_conf as dict
    :rtype: bool
    """
    max_scrolling = rule_conf.get('max_scrolling_count')
    stop_the_scroll = 0 < max_scrolling <= rule_conf.get('scrolling_cycle')

    return not stop_the_scroll


def _expand_string_into_dict(string, value, sep='.'):
    """
    Converts a encapsulated string-dict to a sequence of dict. Use separator (default '.') to split the string.
    Example:
        string1.string2.stringN : value  -> {string1: {string2: {string3: value}}

    :param string: The encapsulated "string-dict"
    :param value: Value associated to the last field of the "string-dict"
    :param sep: Separator character. Default: '.'
    :rtype: dict
    """
    if sep not in string:
        return {string: value}
    key, val = string.split(sep, 1)
    return {key: _expand_string_into_dict(val, value)}


def expand_string_into_dict(dictionary, string, value, sep='.'):
    """
    Useful function to "compile" a string-dict string used in metric and percentage rules into a dictionary sequence.

    :param dictionary: The dictionary dict
    :param string:  String Key
    :param value: String Value
    :param sep: Separator character. Default: '.'
    :rtype: dict
    """

    if sep not in string:
        dictionary[string] = value
        return dictionary
    else:
        field1, new_string = string.split(sep, 1)
        dictionary[field1] = _expand_string_into_dict(new_string, value)
    return dictionary

def expand_string_into_array(value, sep=','):
    """
    Expands a separated string into an array of strings.
    """
    if sep not in value:
        return [value]
    else:
        return value.split(sep)

def format_string(format_config, target_value):
    """
    Formats number, supporting %-format and str.format() syntax.

    :param format_config: string format syntax, for example '{:.2%}' or '%.2f'
    :param target_value: number to format
    :rtype: string
    """
    if (format_config.startswith('{')):
        return format_config.format(target_value)
    else:
        return format_config % (target_value)


def format_host_port(host, port):
    host = host.strip()
    if ":" not in host:
        return "{host}:{port}".format(host=host, port=port)
    return host


def parse_hosts(host, port=9200):
    """
    Convert host str like "host1:port1, host2:port2" to list
    :param host str: hostnames (separated with comma ) or single host name
    :param port: default to 9200
    :return: list of hosts
    """
    host_list = host.split(",")
    host_list = [format_host_port(x, port) for x in host_list]
    return host_list


def get_version_from_cluster_info(client):
    esversion = None
    for retry in range(3):
        try:
            esinfo = client.info()['version']
            esversion = esinfo['number']
            if esinfo.get('distribution') == "opensearch":
                # https://opensearch.org/
                if esversion[0] == "1":
                    # OpenSearch 1.x is based on Elasticsearch 7.10.2
                    esversion = "7.10.2"
                else:
                    # OpenSearch 2.x has qualities similar to 8.2.0
                    esversion = "8.2.0"
            break
        except TransportError:
            if retry == 2:
                raise
            elastalert_logger.warning('Failed to retrieve cluster version information, retrying in 3 seconds')
            time.sleep(3)

    return esversion
