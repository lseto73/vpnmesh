#!/usr/bin/env python
from . import menus
import json
import copy
import logging
import time
import sys
from .utils import re_pick, stat_inc
from progressbar import Bar, ETA, Percentage, ProgressBar

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

# anynets_api.create_anynet_link(tenant_id, l_site_id, l_wan_if_id, r_site_id, r_wan_if_id, forced, admin_state)
# update_anynet_link(tenant_id, link_id, admin_state)
# delete_anynet_link(tenant_id, anynet_id)


def create_anynet_link(site1_id, wan_if_id1, site2_id, wan_if_id2, forced=False, admin_state=True, sdk_vars=None, sdk_session=None):

    data = {
        "ep1_site_id": site1_id,
        "ep2_site_id": site2_id,
        "ep1_wan_if_id": wan_if_id1,
        "ep2_wan_if_id": wan_if_id2,
        "forced": forced,
        'admin_up': admin_state,
        "description": None,
        "name": None,
        "tags": None,
        "type": None
    }

    # return api_utils.rest_call(url, 'post', data=data, sdk_vars=sdk_vars, sdk_session=sdk_session)
    resp = sdk_session.post.tenant_anynetlinks(data)
    return resp.cgx_status, resp.cgx_content


def update_anynet_link(anynet_id, admin_state=True, sdk_vars=None, sdk_session=None):

    data = {
        'admin_up': admin_state
    }

    # return api_utils.rest_call(url, 'put', data=data, sdk_vars=sdk_vars, sdk_session=sdk_session)
    resp = sdk_session.put.tenant_anynetlinks(anynet_id, data)
    return resp.cgx_status, resp.cgx_content


def delete_anynet_link(anynet_id, sdk_vars=None, sdk_session=None):

    # return api_utils.rest_call(url, 'delete', sdk_vars=sdk_vars, sdk_session=sdk_session)
    resp = sdk_session.delete.tenant_anynetlinks(anynet_id)
    return resp.cgx_status, resp.cgx_content


def delete_anynets_menu(current_anynets, sdk_vars, sdk_session):

    modifiable_anynets = {}

    # only do the modifiable ones
    for key, value in current_anynets.items():
        # if modifiable, add to list
        sub_type = value.get('sub_type', 'other')
        if sub_type == 'on-demand':
            modifiable_anynets[key] = value

    num_anynets = len(list(modifiable_anynets.keys()))

    # quick confirm
    do_we_go = menus.quick_confirm("This command will DELETE {0} current MODIFIABLE VPN Mesh Links.\n"
                                   "Are you really really sure?"\
                                   .format(num_anynets), 'N')

    if do_we_go in ['y']:
        print("Preparing to DISABLE {0} VPN Mesh Links..".format(num_anynets))

        counter = 1
        pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=num_anynets+1).start()
        for anynet_uniqueid, anynet in modifiable_anynets.items():

            status = False
            rest_call_retry = 0

            while not status:
                status, disable_result = delete_anynet_link(anynet['path_id'], sdk_vars=sdk_vars, sdk_session=sdk_session)

                if not status:
                    print("API request to disable Mesh VPN Link {0} failed/timed out. Retrying."\
                        .format(anynet['path_id']))
                    rest_call_retry += 1
                    # have we hit retry limit?
                    # print rest_call_retry
                    # print sdk_vars['modify_rest_retry']
                    # print rest_call_retry >= sdk_vars['modify_rest_retry']
                    if rest_call_retry >= sdk_vars['modify_rest_retry']:
                        # Bail out
                        print("ERROR: Could not disable Mesh VPN Link {0}. Continuing.".format(anynet['path_id']))
                        status = True
                        disable_result = False
                    else:
                        # wait and keep going.
                        time.sleep(1)
            counter += 1
            pbar.update(counter)
    else:
        print("Canceling...")

    return do_we_go


def disable_anynets_menu(current_anynets, sdk_vars, sdk_session):

    num_anynets = len(list(current_anynets.keys()))

    # quick confirm
    do_we_go = menus.quick_confirm("***THIS COMMAND CAN TAKE DOWN BRANCH->DC VPNS***\n"
                                   "This command will Admin Disable {0} current VPN Mesh Links.\n"
                                   "Are you really really sure? "\
                                   .format(num_anynets), 'N')

    if do_we_go in ['y']:
        print("Preparing to DISABLE {0} VPN Mesh Links..".format(num_anynets))

        counter = 1
        pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=num_anynets+1).start()
        for anynet_uniqueid, anynet in current_anynets.items():

            status = False
            rest_call_retry = 0

            while not status:
                status, disable_result = update_anynet_link(anynet['path_id'], admin_state=False,
                                                            sdk_vars=sdk_vars, sdk_session=sdk_session)

                if not status:
                    print("API request to disable Mesh VPN Link {0} failed/timed out. Retrying."\
                        .format(anynet['path_id']))
                    rest_call_retry += 1
                    # have we hit retry limit?
                    # print rest_call_retry
                    # print sdk_vars['modify_rest_retry']
                    # print rest_call_retry >= sdk_vars['modify_rest_retry']
                    if rest_call_retry >= sdk_vars['modify_rest_retry']:
                        # Bail out
                        print("ERROR: Could not disable Mesh VPN Link {0}. Continuing.".format(anynet['path_id']))
                        status = True
                        disable_result = False
                    else:
                        # wait and keep going.
                        time.sleep(1)
            counter += 1
            pbar.update(counter)
    else:
        print("Canceling...")

    return do_we_go


def enable_anynets_menu(current_anynets, sdk_vars, sdk_session):

    num_anynets = len(list(current_anynets.keys()))

    # quick confirm
    do_we_go = menus.quick_confirm("This command will Admin Enable {0} current VPN Mesh Links.\n"
                                   "Are you sure? "\
                                   .format(num_anynets), 'N')

    if do_we_go in ['y']:
        print("Preparing to ENABLE {0} VPN Mesh Links..".format(num_anynets))

        counter = 1
        pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=num_anynets+1).start()
        for anynet_uniqueid, anynet in current_anynets.items():

            status = False
            rest_call_retry = 0

            while not status:
                status, enable_result = update_anynet_link(anynet['path_id'], admin_state=True,
                                                           sdk_vars=sdk_vars, sdk_session=sdk_session)

                if not status:
                    print("API request to enable Mesh VPN Link {0} failed/timed out. Retrying."\
                        .format(anynet['path_id']))
                    rest_call_retry += 1
                    # have we hit retry limit?
                    # print rest_call_retry
                    # print sdk_vars['modify_rest_retry']
                    # print rest_call_retry >= sdk_vars['modify_rest_retry']
                    if rest_call_retry >= sdk_vars['modify_rest_retry']:
                        # Bail out
                        print("ERROR: Could not disable Mesh VPN Link {0}. Continuing.".format(anynet['path_id']))
                        status = True
                        enable_result = False
                    else:
                        # wait and keep going.
                        time.sleep(1)
            counter += 1
            pbar.update(counter)
    else:
        print("Canceling...")

    return do_we_go


def create_anynets_menu(new_anynets, sdk_vars, sdk_session):

    num_anynets = len(list(new_anynets.keys()))

    # quick confirm
    do_we_go = menus.quick_confirm("This command will create {0} new VPN Mesh Links. \nAre you sure? "\
                                   .format(num_anynets), 'N')

    if do_we_go in ['y']:
        print("Preparing to deploy {0} VPN Mesh Links..".format(num_anynets))

        counter = 1
        pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=num_anynets+1).start()
        for anynet_uniqueid, anynet in new_anynets.items():

            status = False
            rest_call_retry = 0

            while not status:
                status, create_result = create_anynet_link(anynet['source_site_id'], anynet['source_wan_if_id'],
                                                           anynet['target_site_id'], anynet['target_wan_if_id'],
                                                           forced=True, admin_state=True, sdk_vars=sdk_vars,
                                                           sdk_session=sdk_session)
#                print(status, create_result)
                if not status:
                    print("API request to create Mesh VPN Link {0}({1}) <-> {2}({3}) failed/timed out. Retrying."\
                        .format(anynet['source_site_id'], anynet['source_wan_if_id'],
                                anynet['target_site_id'], anynet['target_wan_if_id']))
                    rest_call_retry += 1
                    # have we hit retry limit?
                    # if rest_call_retry >= sdk_vars['modify_rest_retry']:
                        # Bail out
                    if rest_call_retry >= 8:
                        print("ERROR: Could not create Mesh VPN Link {0}({1}) <-> {2}({3}). Continuing."\
                        .format(anynet['source_site_id'], anynet['source_wan_if_id'],
                                anynet['target_site_id'], anynet['target_wan_if_id']))
                        status = True
                        create_result = False
                    else:
                        # wait and keep going.
                        time.sleep(1)

            counter += 1
            pbar.update(counter)
    else:
        print("Canceling...")

    return do_we_go


def print_selection_overview(anynet_text_list, anynet_label):

    statistics = {
        'modifiable_anynets': 0,
        'always_anynets': 0,
        'other_anynets': 0,
        'new_anynets': 0
    }

    for anynet in anynet_text_list:
        if anynet.endswith(" - Modifiable"):
            stat_inc(statistics, 'modifiable_anynets')
        elif anynet.endswith(" - Always On"):
            stat_inc(statistics, 'always_anynets')
        elif anynet.endswith(" - New"):
            stat_inc(statistics, 'new_anynets')
        else:
            stat_inc(statistics, 'other_anynets')

    print('{:>30}: {:>9}'.format(anynet_label, len(anynet_text_list)))
    if statistics['always_anynets']:
        print('{:>30}: {:>9}'.format('Always', statistics['always_anynets']))
    if statistics['modifiable_anynets']:
        print('{:>30}: {:>9}'.format('Modifiable', statistics['modifiable_anynets']))
    if statistics['new_anynets']:
        print('{:>30}: {:>9}'.format('Creatable', statistics['new_anynets']))
    if statistics['other_anynets']:
        print('{:>30}: {:>9}'.format('Other', statistics['other_anynets']))

    return


def calculate_anynet_links(current_anynets, new_anynets, id_sitename_dict,
                           swi_to_wn_dict, id_wan_network_name_dict, site_id_to_role):

    current_anynets_text_list = []
    new_anynets_text_list = []

    role_xlate = {
        'HUB': 'DC',
        'SPOKE': 'Branch'
    }
    type_xlate = {
        'always-on': 'Always On',
        # always-on is auto in 4.4.1+
        'auto': 'Always On',
        'on-demand': 'Modifiable'
    }

    # current_anynets first.
    for anynet_unique_key, anynet in current_anynets.items():
        # "Site 1[Site 1 Role](Site 1 WAN Network) <-> Site 2[Site 2 Role](Site 2 WAN Network)"
        # make sure first link is DC if DC-Branch anynet
        first_text = 'source'
        second_text = 'target'
        test_role = site_id_to_role.get(anynet['target_site_id'], 'OTHER')
        if test_role == "HUB":
            first_text = 'target'
            second_text = 'source'

        anynet_text = "[{1}] {0} ({2}) <-> [{4}] {3} ({5}) - {6}"\
            .format(id_sitename_dict.get(anynet[first_text + '_site_id'], 'UNKNOWN'),
                    role_xlate.get(site_id_to_role.get(anynet[first_text + '_site_id'], 'Other'), 'Other'),
                    id_wan_network_name_dict.get(swi_to_wn_dict.get(anynet[first_text + '_wan_if_id'], 'UNKNOWN'),
                                                 'UNKNOWN'),
                    id_sitename_dict.get(anynet[second_text + '_site_id'], 'UNKNOWN'),
                    role_xlate.get(site_id_to_role.get(anynet[second_text + '_site_id'], 'Other'), 'Other'),
                    id_wan_network_name_dict.get(swi_to_wn_dict.get(anynet[second_text + '_wan_if_id'], 'UNKNOWN'),
                                                 'UNKNOWN'),
                    type_xlate.get(anynet['sub_type'], 'other'))
        current_anynets_text_list.append(anynet_text)


    # new anynets
    for anynet_unique_key, anynet in new_anynets.items():

        # "Site 1[Site 1 Role](Site 1 WAN Network) <-> Site 2[Site 2 Role](Site 2 WAN Network)"
        # make sure first link is DC if DC-Branch anynet
        first_text = 'source'
        second_text = 'target'
        test_role = site_id_to_role.get(anynet['target_site_id'], 'OTHER')
        if test_role == "HUB":
            first_text = 'target'
            second_text = 'source'

        anynet_text = "[{1}] {0} ({2}) <-> [{4}] {3} ({5}) - {6}" \
            .format(id_sitename_dict.get(anynet[first_text + '_site_id'], 'UNKNOWN'),
                    role_xlate.get(site_id_to_role.get(anynet[first_text + '_site_id'], 'Other'), 'Other'),
                    id_wan_network_name_dict.get(swi_to_wn_dict.get(anynet[first_text + '_wan_if_id'], 'UNKNOWN'),
                                                 'UNKNOWN'),
                    id_sitename_dict.get(anynet[second_text + '_site_id'], 'UNKNOWN'),
                    role_xlate.get(site_id_to_role.get(anynet[second_text + '_site_id'], 'Other'), 'Other'),
                    id_wan_network_name_dict.get(swi_to_wn_dict.get(anynet[second_text + '_wan_if_id'], 'UNKNOWN'),
                                                 'UNKNOWN'),
                    'New')
        new_anynets_text_list.append(anynet_text)

    return current_anynets_text_list, new_anynets_text_list


def main_anynet_menu(new_anynets, current_anynets,
                  site_swi_all_dict, swi_to_wn_dict, wn_to_swi_dict,
                  id_wan_network_name_dict, wan_network_name_id_dict,
                  swi_to_site_dict, id_sitename_dict, mesh_type, site_id_to_role_dict,
                  sdk_vars, sdk_session):
    """
    Main menu for anynet manipulation
    :param new_anynets: List of new anynet objects that can be created.
    :param current_anynets: List of current anynet objects
    :param site_swi_all_dict: Site-SWI dict for ALL sites selected.
    :param swi_to_wn_dict: xlation dict for SWI to Wan Network ID
    :param wn_to_swi_dict: xlation dict for WAN Network ID to SWI
    :param id_wan_network_name_dict: xlation dict for WAN Network ID to WAN Network Name
    :param wan_network_name_id_dict: xlation dict for WAN Network Name to WAN Network ID
    :param swi_to_site_dict: xlation dict for SWI to Site ID
    :param id_sitename_dict: xlation dict for site ID to site Name
    :param mesh_type: 'internet-stub' or 'priv-wan-stub'
    :param site_id_to_role_dict: site ID to Site Role text.
    :param tenantid: tenant ID
    :return: tuple with: action (string or true/false)
             site_a_action_dict (Site-SWI dict for list A)
             site_b_action_dict (Site-SWI dict for list B)
    """

    tenantid = sdk_session.tenant_id

    current_anynet_text_list, new_anynet_text_list = calculate_anynet_links(current_anynets, new_anynets,
                                                                                        id_sitename_dict,
                                                                                        swi_to_wn_dict,
                                                                                        id_wan_network_name_dict,
                                                                                        site_id_to_role_dict)

    logger.debug("CURRENT_MESH ({0}): {1}".format(len(current_anynet_text_list),
                                                  json.dumps(current_anynet_text_list, indent=4)))
    logger.debug("NEW_MESH ({0}): {1}".format(len(new_anynet_text_list),
                                              json.dumps(new_anynet_text_list, indent=4)))

    loop = True
    reload_main_menu = False
    links_modified = False
    while loop:

        # Print header
        if not links_modified:
            print("")
            print_selection_overview(current_anynet_text_list, "Matching Current Links")
            print("")
            print_selection_overview(new_anynet_text_list, "\"New\" links to finish Mesh")
            print("")
        else:
            print("")
            print("s")
            print("\tLinks have been modified. Please \"Refresh\" (option 7) to return to")
            print("\t      previous menus and update stats on this page.")
            print("")

        action = [
            ("View Matching Current Links", 'view_c'),
            ("View New Links", 'view_n'),
            ("Admin Disable All Matching Current Links (4.4.1+)", 'disable_c'),
            ("Admin Enable All Matching Current Links (4.4.1+)", 'enable_c'),
            ("Delete All Matching Current Modifiable Links", 'delete_c'),
            ("Create All New Links", 'create_n'),
            ("Refresh Link Status (reload main menu)", 'reload'),
            ("Quit", 'quit')
        ]

        banner = "Select Action:"
        line_fmt = "{0}: {1}"

        # just pull 2nd value
        list_name, selected_action = menus.quick_menu(banner, line_fmt, action)

        if selected_action == 'view_c':
            print("\n{0} ({1} entries):".format("Matching Current Links:", len(current_anynet_text_list)))
            for item in current_anynet_text_list:
                print("\t{0}".format(item))
        elif selected_action == 'view_n':
            print("\n{0} ({1} entries):".format("New Links:", len(new_anynet_text_list)))
            for item in new_anynet_text_list:
                print("\t{0}".format(item))
        elif selected_action == 'disable_c':
            result = disable_anynets_menu(current_anynets, sdk_vars, sdk_session)
            # set links modified bit if operation was attempted.
            if result:
                links_modified = True
        elif selected_action == 'enable_c':
            result = enable_anynets_menu(current_anynets, sdk_vars, sdk_session)
            # set links modified bit if operation was attempted.
            if result:
                links_modified = True
        elif selected_action == 'delete_c':
            result = delete_anynets_menu(current_anynets, sdk_vars, sdk_session)
            # set links modified bit if operation was attempted.
            if result:
                links_modified = True
        elif selected_action == 'create_n':
            result = create_anynets_menu(new_anynets, sdk_vars, sdk_session)
            # set links modified bit if operation was attempted.
            if result:
                links_modified = True
        elif selected_action == 'reload':
            reload_main_menu = True
            loop = False
        else:
            sdk_session.interactive.logout()
            sys.exit()

    return reload_main_menu
