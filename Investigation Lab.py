"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    # call 'file_reputation' block
    file_reputation(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_Filter_Banned_Countries, name="geolocate_ip_1")

    return

def positive_threshold_exceeded(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('positive_threshold_exceeded() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation:action_result.summary.positives", ">", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Filter_out_non_IPs(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    add_comment_4(action=action, success=success, container=container, results=results, handle=handle)

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virustotal'], callback=join_Filter_Banned_Countries, name="domain_reputation_1")

    return

def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation() called')

    # collect data for 'file_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=decision_4, name="file_reputation")

    return

def Notify_IT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Notify_IT() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """A potentially malicious file download has been detected on a local server with IP
address {0}. Notify IT team?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_out_non_IPs:condition_1:artifact:*.cef.destinationAddress",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Notify_IT", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def Filter_out_non_IPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Filter_out_non_IPs() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Filter_out_non_IPs:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Notify_IT(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Store_Country_Name(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    pin_7(action=action, success=success, container=container, results=results, handle=handle)

    return

def Promote_to_Case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Promote_to_Case() called')
    
    # call playbook "PhantomClass/Case Promotion Lab", returns the playbook_run_id
    playbook_run_id = phantom.playbook("PhantomClass/Case Promotion Lab", container=container)

    return

def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_comment_4() called')

    phantom.comment(container=container, comment="Threat level found to be low")
    pin_5(container=container)

    return

def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_5() called')

    phantom.pin(container=container, data="", message="Processed and found harmless", name=None)
    join_set_status_6(container=container)

    return

def set_status_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_status_6() called')

    phantom.set_status(container=container, status="Closed")

    return

def join_set_status_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_set_status_6() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_ip_1', 'domain_reputation_1', 'file_reputation', 'Notify_IT' ]):
        
        # call connected block "set_status_6"
        set_status_6(container=container, handle=handle)
    
    return

def pin_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_7() called')

    phantom.pin(container=container, data="", message="Analyst has chosen not to promote to a case", pin_type="card", pin_style="grey", name=None)
    join_set_status_6(container=container)

    return

def Filter_Banned_Countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Filter_Banned_Countries() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:Banned Countries"],
        ],
        name="Filter_Banned_Countries:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        positive_threshold_exceeded(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "not in", "custom_list:Banned Countries"],
        ],
        name="Filter_Banned_Countries:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        country_source_not_threatening(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_Filter_Banned_Countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_Filter_Banned_Countries() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'geolocate_ip_1', 'domain_reputation_1', 'file_reputation' ]):
        
        # call connected block "Filter_Banned_Countries"
        Filter_Banned_Countries(container=container, handle=handle)
    
    return

def country_source_not_threatening(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('country_source_not_threatening() called')

    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.data.*.country_name'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, data=results_item_1_0, message="Determined origin country is not on high-risk list", pin_type="card", pin_style="", name="non high-risk country")

    return

def add_hash_to_seen_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_hash_to_seen_list() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    container_item_0 = [item[0] for item in container_data]

    phantom.add_list("Prior Hashes", container_item_0)
    join_Filter_Banned_Countries(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation:action_result.parameter.hash", "not in", "custom_list:Prior Hashes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        add_hash_to_seen_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def Store_Country_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Store_Country_Name() called')
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:Filter_Banned_Countries:condition_1:geolocate_ip_1:action_result.data.*.country_name"])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    url = ''
    for item in filtered_results_data_1:
        if item[0]:
            url = item[0]
        
    # store country name into object db
    phantom.save_object(key="country_name_Email_Notify",
    value={'value': "'" + url + "'"}, auto_delete=True, container_id=container['id'])

    ################################################################################
    ## Custom Code End
    ################################################################################
    Promote_to_Case(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    return