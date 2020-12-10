#!/usr/bin/env python
"""
CGNX API -> Manage VPN Mesh

aaron@cloudgenix.com

"""
# standard modules
import argparse
import getpass
import json
import logging
import time
import urlparse
import sys

import cloudgenix
from functions import sites, menus, vpn, anynets
from progressbar import Bar, ETA, Percentage, ProgressBar

# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SCRIPT_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix VPN_Mesh management'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

# Generic structure to keep authentication info

sdk_vars = {
    "load_list_a": None,            # Filename to load site list a
    "load_list_b": None,            # Filename to load site list b
    "load_wn_list_a": None,         # Filename to load wan network list a
    "load_wn_list_b": None,         # Filename to load wan network list b
    "reload_list_a": None,          # list of sites a to be used on re-loop of logic
    "reload_list_b": None,          # list of sites b to be used on re-loop of logic
    "reload_wn_list_a": None,       # list of WAN Networks a to be used on re-loop of logic
    "reload_wn_list_b": None,       # list of WAN Networks b to be used on re-loop of logic
    "loop_counter": 0               # Loop counter, arg files only loaded on first loop.
}


def siteid_to_name_dict(sdk_vars, sdk_session):
    """
    Create a Site ID <-> Name xlation constructs
    :param passed_sdk_vars: sdk_vars global info struct
    :return: xlate_dict, a dict with siteid key to site name. site_list, a list of site IDs
    """
    id_xlate_dict = {}
    name_xlate_dict = {}
    site_id_list = []
    site_name_list = []
    site_id_to_role = {}

    resp = sdk_session.get.sites()
    status = resp.cgx_status
    raw_sites = resp.cgx_content

    sites_list = raw_sites.get('items', None)

    if not status or not sites_list:
        print "ERROR: unable to get sites for account '{0}'.".format(sdk_vars['tenant_name'])
        return {}, {}, [], []

    # build translation dict
    for site in sites_list:
        name = site.get('name')
        site_id = site.get('id')
        role = site.get('element_cluster_role')

        if name and site_id:
            id_xlate_dict[site_id] = name
            name_xlate_dict[name] = site_id
            site_id_list.append(site_id)
            site_name_list.append(name)

        if site_id and role:
            site_id_to_role[site_id] = role

    return id_xlate_dict, name_xlate_dict, site_id_list, site_name_list, site_id_to_role


def wannetworkid_to_name_dict(sdk_vars, sdk_session):
    """
    Create a Site ID <-> Name xlation constructs
    :param passed_sdk_vars: sdk_vars global info struct
    :return: xlate_dict, a dict with wannetworkid key to wan_network name. wan_network_list, a list of wan_network IDs
    """
    id_xlate_dict = {}
    name_xlate_dict = {}
    wan_network_id_list = []
    wan_network_name_list = []
    wan_network_id_type = {}

    resp = sdk_session.get.wannetworks()
    status = resp.cgx_status
    raw_wan_networks = resp.cgx_content

    wan_networks_list = raw_wan_networks.get('items', None)

    if not status or not wan_networks_list:
        print "ERROR: unable to get wan networks for account '{0}'.".format(sdk_vars['tenant_name'])
        return {}, {}, [], []

    # build translation dict
    for wan_network in wan_networks_list:
        name = wan_network.get('name')
        wan_network_id = wan_network.get('id')
        wn_type = wan_network.get('type')

        if name and wan_network_id:
            id_xlate_dict[wan_network_id] = name
            name_xlate_dict[name] = wan_network_id
            wan_network_id_list.append(wan_network_id)
            wan_network_name_list.append(name)

        if wan_network_id and wn_type:
            wan_network_id_type[wan_network_id] = wn_type

    return id_xlate_dict, name_xlate_dict, wan_network_id_list, wan_network_name_list, wan_network_id_type


def go():

    # check for initial launch
    if sdk_vars["loop_counter"] == 0:

        sdk_vars['load_list_a'] = args['load_list_a']
        sdk_vars['load_list_b'] = args['load_list_b']
        sdk_vars['load_wn_list_a'] = args['load_wn_list_a']
        sdk_vars['load_wn_list_b'] = args['load_wn_list_b']

        if args["debug"] == 1:
            logging.basicConfig(level=logging.INFO,
                                format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
            clilogger = logging.getLogger()
            clilogger.setLevel(logging.INFO,)
        elif args["debug"] >= 2:
            logging.basicConfig(level=logging.DEBUG,
                                format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
            clilogger = logging.getLogger()
            clilogger.setLevel(logging.DEBUG)
        else:
            # set logging off unless asked for
            pass

        # Log
        logger.debug("LOOP_COUNTER: {0}".format(sdk_vars["loop_counter"]))

        logger.info("Initial Launch:")

        # create file-system friendly tenant str.
        sdk_vars["tenant_str"] = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

        # load site lists for first run.
        if sdk_vars['load_list_a']:
            try:
                with open(sdk_vars['load_list_a']) as data_file:
                    data = json.load(data_file)
                site_list_a = data[:]
                print "\n Site List A:\n\tSuccessfully loaded {0} entries from {1}.".format(len(data), sdk_vars['load_list_a'])
            except (ValueError, IOError) as e:
                print "ERROR, Site List A: Could not load {0}: {1}.".format(sdk_vars['load_list_a'], e)
                site_list_a = []
        else:
            site_list_a = []

        if sdk_vars['load_list_b']:
            try:
                with open(sdk_vars['load_list_b']) as data_file:
                    data = json.load(data_file)
                site_list_b = data[:]
                print "\n Site List B:\n\tSuccessfully loaded {0} entries from {1}.".format(len(data), sdk_vars['load_list_b'])
            except (ValueError, IOError) as e:
                print "ERROR, Site List B: Could not load {0}: {1}.".format(sdk_vars['load_list_b'], e)
                site_list_b = []
        else:
            site_list_b = []

        # load wan network for first run.
        if sdk_vars['load_wn_list_a']:
            try:
                with open(sdk_vars['load_wn_list_a']) as data_file:
                    data = json.load(data_file)
                sdk_vars['reload_wn_list_a'] = data[:]
                print "\n Site WAN Network List A:\n\tSuccessfully loaded {0} entries from {1}.".format(len(data), sdk_vars['load_wn_list_a'])
            except (ValueError, IOError) as e:
                print "ERROR, Site WAN Network List A: Could not load {0}: {1}.".format(sdk_vars['load_wn_list_a'], e)
                sdk_vars['reload_wn_list_a'] = []
        else:
            sdk_vars['reload_wn_list_a'] = []

        if sdk_vars['load_wn_list_b']:
            try:
                with open(sdk_vars['load_wn_list_a']) as data_file:
                    data = json.load(data_file)
                sdk_vars['reload_wn_list_b'] = data[:]
                print "\n Site WAN Network List B:\n\t Successfully loaded {0} entries from {1}.".format(len(data), sdk_vars['load_wn_list_b'])
            except (ValueError, IOError) as e:
                print "ERROR, Site WAN Network List B: Could not load {0}: {1}.".format(sdk_vars['load_wn_list_b'], e)
                sdk_vars['reload_wn_list_b'] = []
        else:
            sdk_vars['reload_wn_list_b'] = []

    else:
        # re-loop, pull previous list out of sdk_vars dict.
        site_list_a = sdk_vars["reload_list_a"]
        site_list_b = sdk_vars["reload_list_b"]

    # Get/update list of sites, create python dictionary to map site ID to name.
    print "Caching all site information, please wait..."
    id_sitename_dict, sitename_id_dict, site_id_list, site_name_list, site_id_to_role_dict \
        = siteid_to_name_dict(sdk_vars, cgx_session)
    id_wan_network_name_dict, wan_network_name_id_dict, wan_network_id_list, wan_network_name_list, \
        wan_network_to_type_dict = wannetworkid_to_name_dict(sdk_vars, cgx_session)

    logger.debug("SITE -> ROLE ({0}): {1}".format(len(site_id_to_role_dict),
                                                  json.dumps(site_id_to_role_dict, indent=4)))

    # Begin Site Selection Loop
    loop = True
    while loop:

        # Print header
        print ""
        sites.print_selection_overview(site_list_a, site_list_b, sitename_id_dict, site_id_to_role_dict)
        print ""

        action = [
            ("Edit Site List A", 'edit_sitelista'),
            ("Edit Site List B", 'edit_sitelistb'),
            ("Continue", 'continue')
        ]

        banner = "Select Action:"
        line_fmt = "{0}: {1}"

        # just pull 2nd value
        list_name, selected_action = menus.quick_menu(banner, line_fmt, action)

        if selected_action == 'edit_sitelista':
            site_list_a = sites.edit_site_list(site_list_a, "Site List A", site_name_list, sdk_vars["tenant_str"])
        elif selected_action == 'edit_sitelistb':
            site_list_b = sites.edit_site_list(site_list_b, "Site List B", site_name_list, sdk_vars["tenant_str"])
        elif selected_action == "continue":
            if (len(site_list_a) < 1) or (len(site_list_b) < 1):
                print "\nERROR, must select at least one site in each list."
            else:
                # Good to go, continue.
                loop = False
        else:
            cgx_session.interactive.logout()
            sys.exit()

    # save lists for re-use next loop.
    sdk_vars["reload_list_a"] = site_list_a
    sdk_vars["reload_list_b"] = site_list_b

    # sites selected, determine if this will be Internet or VPNoMPLS mesh
    action = [
        ("Internet VPN (Public)", 'publicwan'),
        ("Private WAN VPN (Private, VPN over MPLS, release 4.4.1+ only)", 'privatewan'),
    ]

    banner = "Managing which type of VPN mesh:"
    line_fmt = "{0}: {1}"

    mesh_type = menus.quick_menu(banner, line_fmt, action)[1]

    # map type-specific anynet based on choice above
    anynet_specific_type = 'anynet'
    if mesh_type in ['privatewan']:
        anynet_specific_type = "private-anynet"
    elif mesh_type in ['publicwan']:
        anynet_specific_type = "public-anynet"

    # convert site lists (by name) to ID lists. Look up ID in previous sitename_id dict. if exists, enter.
    site_id_list_a = []
    for site in site_list_a:
        site_id = sitename_id_dict.get(site, None)
        if site_id:
            site_id_list_a.append(site_id)

    site_id_list_b = []
    for site in site_list_b:
        site_id = sitename_id_dict.get(site, None)
        if site_id:
            site_id_list_b.append(site_id)

    # combine site lists and remove duplicates so we can pull topology info from API once per site.
    combined_site_id_list = list(site_id_list_a)
    combined_site_id_list.extend(x for x in site_id_list_b if x not in site_id_list_a)

    # print json.dumps(combined_site_id_list, indent=4)

    # get/update topology

    print "Loading VPN topology information for {0} sites, please wait...".format(len(combined_site_id_list))

    logger.debug('COMBINED_SITE_ID_LIST ({0}): {1}'.format(len(combined_site_id_list),
                                                           json.dumps(combined_site_id_list, indent=4)))

    swi_to_wan_network_dict = {}
    swi_to_site_dict = {}
    wan_network_to_swi_dict = {}
    all_anynets = {}
    site_swi_dict = {}

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=len(combined_site_id_list)+1).start()
    site_processed = 1

    for site in combined_site_id_list:
        site_swi_list = []

        query = {
            "type": "basenet",
            "nodes": [
                site
            ]
        }

        status = False
        rest_call_retry = 0

        while not status:
            resp = cgx_session.post.topology(query)
            status = resp.cgx_status
            topology = resp.cgx_content

            if not status:
                print "API request for topology for site ID {0} failed/timed out. Retrying.".format(site)
                rest_call_retry += 1
                # have we hit retry limit?
                if rest_call_retry >= sdk_vars['rest_call_max_retry']:
                    # Bail out
                    print "ERROR: could not query site ID {0}. Continuing.".format(site)
                    status = True
                    topology = False
                else:
                    # wait and keep going.
                    time.sleep(1)

        if status and topology:
            # iterate topology. We need to iterate all of the matching SWIs, and existing anynet connections (sorted).
            logger.debug("TOPOLOGY: {0}".format(json.dumps(topology, indent=4)))

            for link in topology.get('links', []):
                link_type = link.get('type', "")

                # if an anynet link (SWI to SWI)
                if link_type in ["anynet", anynet_specific_type]:
                    # vpn record, check for uniqueness.
                    # 4.4.1
                    source_swi = link.get('source_wan_if_id')
                    if not source_swi:
                        # 4.3.x compatibility
                        source_swi = link.get('source_wan_path_id')
                        if source_swi:
                            link['source_wan_if_id'] = source_swi
                    # 4.4.1
                    dest_swi = link.get('target_wan_if_id')
                    if not dest_swi:
                        # 4.3.x compatibility
                        dest_swi = link.get('target_wan_path_id')
                        if dest_swi:
                            link['target_wan_if_id'] = dest_swi
                    # create anynet lookup key
                    anynet_lookup_key = "_".join(sorted([source_swi, dest_swi]))
                    if not all_anynets.get(anynet_lookup_key, None):
                        # path is not in current anynets, add
                        all_anynets[anynet_lookup_key] = link

        # Query 2 - now need to query SWI for site, since stub-topology may not be in topology info.
        status = False

        while not status:
            resp = cgx_session.get.waninterfaces(site)
            status = resp.cgx_status
            site_wan_if_result = resp.cgx_content

            if not status:
                print "API request for Site WAN Interfaces for site ID {0} failed/timed out. Retrying.".format(site)
                time.sleep(1)

        if status and site_wan_if_result:
            site_wan_if_items = site_wan_if_result.get('items', [])
            logger.debug('SITE WAN IF ITEMS ({0}): {1}'.format(len(site_wan_if_items),
                                                               json.dumps(site_wan_if_items, indent=4)))

            # iterate all the site wan interfaces
            for current_swi in site_wan_if_items:
                # get the WN bound to the SWI.
                wan_network_id = current_swi.get('network_id', "")
                swi_id = current_swi.get('id', "")

                if swi_id:
                    # update SWI -> Site xlation dict
                    swi_to_site_dict[swi_id] = site

                # get the SWIs that match the mesh_type
                if wan_network_id and swi_id and wan_network_to_type_dict.get(wan_network_id, "") == mesh_type:
                    logger.debug('SWI_ID = SITE: {0} = {1}'.format(swi_id, site))

                    # query existing wan_network_to_swi dict if entry exists.
                    existing_swi_list = wan_network_to_swi_dict.get(wan_network_id, [])

                    # update swi -> WN xlate dict
                    swi_to_wan_network_dict[swi_id] = wan_network_id

                    # update site-level SWI list.
                    site_swi_list.append(swi_id)

                    # update WN -> swi xlate dict
                    existing_swi_list.append(swi_id)
                    wan_network_to_swi_dict[wan_network_id] = existing_swi_list

        # add all matching mesh_type stubs to site_swi_dict
        site_swi_dict[site] = site_swi_list

        # iterate bar and counter.
        site_processed += 1
        pbar.update(site_processed)

    # finish after iteration.
    pbar.finish()

    # update all_anynets with site info. Can't do this above, because xlation table not finished when needed.
    for anynet_key, link in all_anynets.iteritems():
        # 4.4.1
        source_swi = link.get('source_wan_if_id')
        if not source_swi:
            # 4.3.x compatibility
            source_swi = link.get('source_wan_path_id')
        # 4.4.1
        dest_swi = link.get('target_wan_if_id')
        if not dest_swi:
            # 4.3.x compatibility
            dest_swi = link.get('target_wan_path_id')
        link['source_site_id'] = swi_to_site_dict.get(source_swi, 'UNKNOWN (Unable to map SWI to Site ID)')
        link['target_site_id'] = swi_to_site_dict.get(dest_swi, 'UNKNOWN (Unable to map SWI to Site ID)')

    logger.debug("SWI -> WN xlate ({0}): {1}".format(len(swi_to_wan_network_dict),
                                               json.dumps(swi_to_wan_network_dict, indent=4)))
    logger.debug("All Anynets ({0}): {1}".format(len(all_anynets),
                                                     json.dumps(all_anynets, indent=4)))
    logger.debug("SWI construct ({0}): {1}".format(len(site_swi_dict),
                                                   json.dumps(site_swi_dict, indent=4)))
    logger.debug("WN xlate ({0}): {1}".format(len(wan_network_to_swi_dict),
                                              json.dumps(wan_network_to_swi_dict, indent=4)))
    logger.debug("SWI -> SITE xlate ({0}): {1}".format(len(swi_to_site_dict),
                                              json.dumps(swi_to_site_dict, indent=4)))

    new_anynets, current_anynets = vpn.main_vpn_menu(site_id_list_a,
                                                     site_id_list_b,
                                                     all_anynets,
                                                     site_swi_dict,
                                                     swi_to_wan_network_dict,
                                                     wan_network_to_swi_dict,
                                                     id_wan_network_name_dict,
                                                     wan_network_name_id_dict,
                                                     swi_to_site_dict,
                                                     id_sitename_dict,
                                                     mesh_type,
                                                     site_id_to_role_dict, sdk_vars=sdk_vars, sdk_session=cgx_session)

    reload_or_exit = anynets.main_anynet_menu(new_anynets,
                                              current_anynets,
                                              site_swi_dict,
                                              swi_to_wan_network_dict,
                                              wan_network_to_swi_dict,
                                              id_wan_network_name_dict,
                                              wan_network_name_id_dict,
                                              swi_to_site_dict,
                                              id_sitename_dict,
                                              mesh_type,
                                              site_id_to_role_dict,
                                              sdk_vars, cgx_session)

    # Increment global loop counter
    sdk_vars["loop_counter"] += 1

    return reload_or_exit


# Start
if __name__ == "__main__":
    # parse arguments
    parser = argparse.ArgumentParser(description="CloudGenix Python API Example.")

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="API URI, ex. https://api.cloudgenix.com",
                                  default=None)

    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    group = debug_group.add_mutually_exclusive_group()
    group.add_argument("--rest", "-R", help="Show REST requests",
                       action='store_true',
                       default=False)
    group.add_argument("--restdetail", "-RD", help="Show REST requests AND responses from server",
                       action='store_true',
                       default=False)
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2",
                             default=0)
    vpn_group = parser.add_argument_group('VPN', 'These options modify starting lists/other items.')
    vpn_group.add_argument("--load-list-a", "-LA", help="JSON file containing Site List A", default=False)
    vpn_group.add_argument("--load-list-b", "-LB", help="JSON file containing Site List B", default=False)
    vpn_group.add_argument("--load-wn-list-a", "-WA", help="JSON file containing Wan Network List A", default=False)
    vpn_group.add_argument("--load-wn-list-b", "-WB", help="JSON file containing Wan Network List B", default=False)

    args = vars(parser.parse_args())

    ############################################################################
    # Instantiate API
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ############################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################

    print "{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller)

    # interactive or cmd-line specified initial login

    while cgx_session.tenant_name is None:
        cgx_session.interactive.login(args["email"], args["pass"])

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # start main loop.
    main_loop = True
    while main_loop:
        main_loop = go()

