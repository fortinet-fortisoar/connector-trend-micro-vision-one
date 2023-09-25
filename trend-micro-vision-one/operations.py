""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json

import arrow
import requests
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions

logger = get_logger('trend-micro-vision-one')

INDICATOR_TYPES = {
    "IP Address": "ip",
    "URL": "url",
    "Domain": "domain",
    "File SHA1": "fileSha1",
    "File SHA256": "fileSha256",
    "Email Address": "senderMailAddress"

}


class TrendMicroVisionOne(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        self.headers = {'Authorization': 'Bearer ' + self.api_key}

    def make_rest_call(self, endpoint, params=None, headers_params=None, payload=None, json_body=None, method='POST'):
        if headers_params:
            self.headers.update(headers_params)
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.info('Request URL {}'.format(service_endpoint))
        try:
            response = requests.request(method, service_endpoint, data=payload, headers=self.headers,
                                        params=params, json=json_body, verify=self.verify_ssl)
            if response.ok:
                if 'application/json' in response.headers.get('Content-Type', ''):
                    return json.loads(response.content.decode('utf-8'))
                else:
                    return response.text
            else:
                logger.error("Error: {0}".format(response.text))
                raise ConnectorError('Status Code: {0}, API Response: {1}'.format(response.status_code, response.text))
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(str(err))


def remove_empty_params(params):
    query_params = {k: v for k, v in params.items() if v is not None and v != ''}
    return query_params


def get_str_to_list(param):
    if param and isinstance(param, str):
        param = param.split(',')
    elif param and isinstance(param, list):
        return param
    else:
        param = []
    params = [val.strip() for val in param if isinstance(param, list)]
    return params


def format_date(input_date):
    try:
        if input_date:
            date_data = arrow.get(input_date)
            format_date = date_data.format('YYYY-MM-DDTHH:mm:ss')
            return format_date + 'Z'
    except Exception as err:
        logger.error(err)


def get_list_alerts(config, params):
    tmv1 = TrendMicroVisionOne(config)
    filter_query = params.pop('query', '')
    params = remove_empty_params(params)
    start_date = params.get('startDateTime')
    if start_date:
        params['startDateTime'] = format_date(start_date)
    end_date = params.get('endDateTime')
    if end_date:
        params['endDateTime'] = format_date(end_date)
    tmv1_query = {'TMV1-Query': filter_query} if filter_query else None
    return tmv1.make_rest_call('/v3.0/workbench/alerts', params=params, headers_params=tmv1_query, method='GET')


def get_alert_details(config, params):
    alert_id = params.get('id')
    endpoint = f'/v3.0/workbench/alerts/{alert_id}'
    tmv1 = TrendMicroVisionOne(config)
    return tmv1.make_rest_call(endpoint, method='GET')


def get_task_details(config, params):
    tmv1 = TrendMicroVisionOne(config)
    task_id = params.get('task_id')
    endpoint = f'/v3.0/response/tasks/{task_id}'
    return tmv1.make_rest_call(endpoint, method='GET')


def get_endpoint_details(config, params):
    tmv1 = TrendMicroVisionOne(config)
    params = remove_empty_params(params)
    query = params.pop('query', '')
    headers_params = {'TMV1-Query': query}
    return tmv1.make_rest_call('/v3.0/eiqs/endpoints', headers_params=headers_params, method='GET')


def get_detection_data(config, params):
    tmv1 = TrendMicroVisionOne(config)
    filter_query = params.get('query')
    params = remove_empty_params(params)
    start_date = params.get('startDateTime')
    if start_date:
        params['startDateTime'] = format_date(start_date)
    end_date = params.get('endDateTime')
    if end_date:
        params['endDateTime'] = format_date(end_date)
    tmv1_query = {'TMV1-Query': filter_query} if filter_query else None
    return tmv1.make_rest_call('/v3.0/search/detections', params, headers_params=tmv1_query, method='GET')


def handle_payload_data(key, list_data, dict_data):
    payload = []
    for data in list_data:
        body = {
            key: data
        }
        if isinstance(dict_data, dict):
            for k, v in dict_data.items():
                body[k] = v
        payload.append(body)
    return payload


def build_payload(params):
    indicator_type = INDICATOR_TYPES.get(params.pop('indicator_type', ''))
    list_indicators = get_str_to_list(params.pop('indicator_value', ''))
    params = remove_empty_params(params)
    payload = handle_payload_data(indicator_type, list_indicators, params)
    return payload


def add_to_block_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    payload = build_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    endpoint = '/v3.0/response/suspiciousObjects'
    return tmv1.make_rest_call(endpoint, json_body=payload, headers_params=headers, method='POST')


def remove_from_block_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    payload = build_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/suspiciousObjects/delete', json_body=payload, headers_params=headers,
                               method='POST')


def build_suspicious_object_payload(params):
    payloads = []
    indicator_type = params.pop('indicator_type', '')
    list_indicators = get_str_to_list(params.pop('indicator_value', ''))
    for indicator in list_indicators:
        data = {
            INDICATOR_TYPES.get(indicator_type): indicator
        }
        if params.get('scanAction'):
            data.update({'scanAction': params.get('scanAction', '').lower()})
        if params.get('riskLevel'):
            data.update({'riskLevel': params.get('riskLevel', '').lower()})
        if params.get('daysToExpiration'):
            data.update({'daysToExpiration': params.get('daysToExpiration')})
        if params.get('description'):
            data.update({'description': params.get('description')})
        payloads.append(data)
    return payloads


def add_to_suspicious_object_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    params = remove_empty_params(params)
    payloads = build_suspicious_object_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/threatintel/suspiciousObjects', headers_params=headers, json_body=payloads)


def remove_from_suspicious_object_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    params = remove_empty_params(params)
    payloads = build_suspicious_object_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/threatintel/suspiciousObjects/delete', headers_params=headers, json_body=payloads)


def add_to_exception_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    payloads = build_payload(params)
    return tmv1.make_rest_call('/v3.0/threatintel/suspiciousObjectExceptions', headers_params=headers,
                               json_body=payloads)


def remove_from_exception_list(config, params):
    tmv1 = TrendMicroVisionOne(config)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    payloads = build_payload(params)
    return tmv1.make_rest_call('/v3.0/threatintel/suspiciousObjectExceptions/delete', headers_params=headers,
                               json_body=payloads)


def delete_email_message(config, params):
    tmv1 = TrendMicroVisionOne(config)
    params = remove_empty_params(params)
    params.pop('delete_by', '')
    payload = build_email_action_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/emails/delete', headers_params=headers, json_body=payload)


def build_email_action_payload(params):
    params = remove_empty_params(params)
    message_ids = get_str_to_list(params.pop('messageId', ''))
    if message_ids:
        payload = handle_payload_data('messageId', message_ids, params)
    else:
        unique_ids = get_str_to_list(params.pop('uniqueId', ''))
        payload = handle_payload_data('uniqueId', unique_ids, params)
    return payload


def quarantine_email_message(config, params):
    tmv1 = TrendMicroVisionOne(config)
    params.pop('quarantine_by', '')
    payload = build_email_action_payload(params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/emails/quarantine', headers_params=headers, json_body=payload)


def handle_endpoint_actions_payload(input_type, params):
    if input_type == 'Computer Names':
        endpoint_names = get_str_to_list(params.pop('endpointName', ''))
        payload = handle_payload_data('endpointName', endpoint_names, params)
    else:
        agent_uuids = get_str_to_list(params.pop('agentGuid', ''))
        payload = handle_payload_data('agentGuid', agent_uuids, params)
    return payload


def isolate_endpoint(config, params):
    tmv1 = TrendMicroVisionOne(config)
    action_type = params.pop('isolate_by', '')
    payload = handle_endpoint_actions_payload(action_type, params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/endpoints/isolate', headers_params=headers, json_body=payload)


def restore_endpoint(config, params):
    tmv1 = TrendMicroVisionOne(config)
    action_type = params.pop('restore_by', '')
    payload = handle_endpoint_actions_payload(action_type, params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/endpoints/restore', headers_params=headers, json_body=payload)


def terminates_process(config, params):
    tmv1 = TrendMicroVisionOne(config)
    action_type = params.pop('terminates_by', '')
    payload = handle_endpoint_actions_payload(action_type, params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/endpoints/terminateProcess', headers_params=headers, json_body=payload)


def collect_file(config, params):
    tmv1 = TrendMicroVisionOne(config)
    action_type = params.pop('collect_by', '')
    payload = handle_endpoint_actions_payload(action_type, params)
    headers = {'Content-Type': 'application/json;charset=utf-8'}
    return tmv1.make_rest_call('/v3.0/response/endpoints/collectFile', headers_params=headers, json_body=payload)


def _check_health(config):
    return get_list_alerts(config, {})


operations = {
    'get_list_alerts': get_list_alerts,
    'get_alert_details': get_alert_details,
    'get_detection_data': get_detection_data,
    'get_endpoint_details': get_endpoint_details,
    'get_task_details': get_task_details,
    'isolate_endpoint': isolate_endpoint,
    'restore_endpoint': restore_endpoint,
    'terminates_process': terminates_process,
    'collect_file': collect_file,
    'add_to_block_list': add_to_block_list,
    'remove_from_block_list': remove_from_block_list,
    'add_to_suspicious_object_list': add_to_suspicious_object_list,
    'remove_from_suspicious_object_list': remove_from_suspicious_object_list,
    'add_to_exception_list': add_to_exception_list,
    'remove_from_exception_list': remove_from_exception_list,
    'delete_email_message': delete_email_message,
    'quarantine_email_message': quarantine_email_message

}

