from __future__ import print_function

import boto3
import botocore
import json
import traceback
import requests
import os

code_pipeline = boto3.client('codepipeline')
security_api_url = os.environ['security_api_url']
webhook_notification_url = os.environ['webhook_url']
repo_url = os.environ['repo_url']
api_key = os.environ['api_key']
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0)',
    'x-api-key': api_key
}

CARD_STRING = '{"@context":"https://schema.org/extensions","@type":"MessageCard","themeColor":"0072C6","title":"Hellhound scan finished"}'
STATUS_CODES = ['finished', 'failed']


def continue_job_later(job_id, scan_id):
    print('Putting job continuation ' + job_id)
    code_pipeline.put_job_success_result(
        jobId=job_id, continuationToken=scan_id)


def put_job_success(job, message):
    print('Putting job success')
    code_pipeline.put_job_success_result(jobId=job)


def put_job_failure(job, message):
    print('Putting job failure')
    code_pipeline.put_job_failure_result(jobId=job, failureDetails={
                                         'message': message, 'type': 'JobFailed'})


def start_scan(user_parameters):
    data = user_parameters
    url = security_api_url + '/scans'
    repo_url = user_parameters['repo_url']
    print('request new scan for ' + repo_url + ' to ' + url)
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 201:
        return response.text
    else:
        print(response.status_code)
        exit(0)


def get_scan_status(scan_id, user_parameters):
    url = security_api_url + '/scans/' + scan_id
    print('request scan status to ' + url)
    response = requests.get(url, headers=headers)
    return response.json()


def get_report(scan_id, user_parameters):
    url = security_api_url + '/results/' + scan_id
    print('request scan report to ' + url)
    return requests.get(url, headers=headers)


def send_notification(report_url, result, user_parameters):
    print('send notification to webhook')

    card = json.loads(CARD_STRING)
    card['title'] = 'Hellhound results scan: {}'.format(result['scan_id'])
    text = '<ul>'
    for vulnerability in report_url['vulnerabilities']:
        text += '<li> <strong> {} </strong> <ul> <li>severity: {}</li><li>filename: {} line: {} </li></ul> </li>'.format(vulnerability['title'], vulnerability['severity'], vulnerability['filename'], vulnerability['line'])
    text += '</ul>'
    card['sections'] = [
        {
            'activitySubtitle' : user_parameters['repo_url']
        },
        
        {
        'title' : '<h1>SUMMARY</h1>',
        'facts' : [{
                'name' : 'high',
                'value' : report_url['summary']['high']
            },
            {
                'name' : 'medium',
                'value' : report_url['summary']['medium']
            },
            {
                'name' : 'low',
                'value' : report_url['summary']['low']
            },
            {
                'name' : 'undefined',
                'value' : report_url['summary']['undefined']
            }]
        },
        {
            'title' : '<h1>VULNERABILITIES</h1>',
            'text' : text
        }
    ]
    card['text'] = 'Result: {}'.format(result['status'])
    print(requests.post(webhook_notification_url, json=card))

def start_job(job_id, user_parameters):
    scan_id_string = json.loads(start_scan(user_parameters))
    scan_id = scan_id_string['scan_id']
    print('Started scan ' + scan_id)
    continue_job_later(job_id, scan_id)


def check_job_status(job_id, scan_id, user_parameters):
    print('Get status for scan id:' + scan_id)
    result = get_scan_status(scan_id, user_parameters)
    print(result)

    print('Scan in status: ' + result.get('status'))
    if result.get('status') in STATUS_CODES:
        report_response = get_report(scan_id, user_parameters)
        if report_response.status_code != 200:
            continue_job_later(job_id, scan_id)
        else:
            response_json = json.loads(report_response.text)
            if response_json['summary']['high'] > 0:
                put_job_failure(job_id, 'Job failed with status: ' +
                                result['status'])
            else:
                put_job_success(job_id, 'Job completed.')

            send_notification(response_json, result, user_parameters)
    else:
        continue_job_later(job_id, scan_id)


def lambda_handler(event, context):
    print(event)
    job_id = event['CodePipeline.job']['id']
    job_data = event['CodePipeline.job']['data']
    user_parameters_string = job_data['actionConfiguration']['configuration']['UserParameters']
    user_parameters = json.loads(user_parameters_string)

    if 'continuationToken' in job_data:
        print('Continue with job')
        check_job_status(
            job_id, job_data['continuationToken'], user_parameters)
    else:
        print('Init new scan')
        start_job(job_id, user_parameters)