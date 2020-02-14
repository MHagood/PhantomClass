"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'promote_to_case_1' block
    promote_to_case_1(container=container)

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="Data Breach")
    Fixed_sourceDNS(container=container)

    return

def Fixed_sourceDNS(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_sourceDNS() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
        ],
        name="Fixed_sourceDNS:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fixed_File_Path(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fixed_File_Path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_File_Path() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.filePath", "!=", ""],
        ],
        name="Fixed_File_Path:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fixed_Address(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fixed_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fixed_Address() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Fixed_Address:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Get_Country_Name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Format_Notification(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_Notification() called')
    
    template = """A file has been detected that has been
determined to be potentially malicious. A case
has been opened.
Case link: {0}
Event Name: {1}
Description: {2}
Source URL: {3}
Target Server IP: {4}
Suspicious File Path: {5}
Origin Country: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "filtered-data:Fixed_sourceDNS:condition_1:artifact:*.cef.sourceDnsDomain",
        "filtered-data:Fixed_Address:condition_1:artifact:*.cef.destinationAddress",
        "filtered-data:Fixed_File_Path:condition_1:artifact:*.cef.filePath",
        "Get_Country_Name:custom_function:countryName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Notification")

    Format_user_query(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    extract_email_address__container_email = json.loads(phantom.get_run_data(key='extract_email_address:container_email'))
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='Format_Notification')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "edu-labserver@splunk.com",
        'attachments': "",
        'to': extract_email_address__container_email,
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "New Case Created",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1", parent_action=action)

    return

def Get_Country_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_Country_Name() called')
    input_parameter_0 = ""

    Get_Country_Name__countryName = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    data = phantom.get_object(key='country_name_Email_Notify', container_id=container['id'])
    Get_Country_Name__countryName = data[0]['value']['value']

    # clear object db
    phantom.clear_object(key='country_name_Email_Notify',container_id=container['id'])

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_Country_Name:countryName', value=json.dumps(Get_Country_Name__countryName))
    Format_Notification(container=container)

    return

def Format_user_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Format_user_query() called')
    
    template = """/ph_user/?_filter_username=%22{0}%22"""

    # parameter list for template variable replacement
    parameters = [
        "container:owner",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_user_query")

    Query_user(container=container)

    return

def Query_user(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Query_user() called')

    # collect data for 'Query_user' call
    formatted_data_1 = phantom.get_format_data(name='Format_user_query')

    parameters = []
    
    # build parameters list for 'Query_user' call
    parameters.append({
        'location': formatted_data_1,
        'verify_certificate': False,
        'headers': "",
    })

    phantom.act("get data", parameters=parameters, assets=['local'], callback=extract_email_address, name="Query_user")

    return

def extract_email_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('extract_email_address() called')
    results_data_1 = phantom.collect2(container=container, datapath=['Query_user:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    extract_email_address__container_email = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    extract_email_address__container_email = results_data_1[0][0]['data'][0]['email']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_email_address:container_email', value=json.dumps(extract_email_address__container_email))
    send_email_1(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return