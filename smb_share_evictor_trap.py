#!/usr/bin/env python3
import argparse
import urllib3
import configparser
import sys
import os
import json
import aiohttp
import asyncio
import socket
import requests

# Load and check config file
def config_check(config):
    # Check if CLUSTER_ADDRESS is set in the config
    if not config["CLUSTER"].get("CLUSTER_ADDRESS"):
        print("Error: CLUSTER_ADDRESS is not set in the config file.")
        sys.exit()
    else:
        CLUSTER_ADDRESS = config["CLUSTER"]["CLUSTER_ADDRESS"]

    # Check if TOKEN is set in the config
    if not config["CLUSTER"].get("TOKEN"):
        print("Error: TOKEN is not set in the config file.")
        sys.exit()
    else:
        TOKEN = config["CLUSTER"]["TOKEN"]

    USE_SSL = config["CLUSTER"].getboolean('USE_SSL')
    return CLUSTER_ADDRESS, TOKEN, USE_SSL

# Basic connectivity check function
def check_cluster_connectivity(address, port=443):
    try:
        with socket.create_connection((address, port), timeout=10) as sock:
            return True
    except (socket.timeout, socket.error) as e:
        print(f"Failed to connect to {address} on port {port}: {e}")
        return False

# Check that user has the right level of access
def check_access_rights():
    url = f"https://{CLUSTER_ADDRESS}/v1/session/who-am-i"
    response = requests.get(url, headers=HEADERS, verify=USE_SSL).json()
    user_privileges = response.get('privileges')
    who_am_i = response.get('name')
    all_rights_required = set(RBAC).issubset(set(user_privileges))
    if not all_rights_required:
        missing_privileges = [item for item in RBAC if item not in user_privileges]
        return(False, missing_privileges, who_am_i)
    else:
        return(True, [], who_am_i)


async def get_smb_sessions(session):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/"
    try:
        async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
            # Attempt to read and decode JSON, but catch ContentTypeError
            sessions = await response.json()
    except aiohttp.client_exceptions.ContentTypeError as e:
        # Print the raw response text that caused the error
        raw_content = await response.text()
        print(f"Failed to decode JSON. Raw content was: {raw_content}")
        raise e  # Re-raise the exception after logging the raw content

    next_page = sessions['paging'].get('next')
    tasks = []
    tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))

    # Paging support
    while next_page:
        url = f"https://{CLUSTER_ADDRESS}/api" + next_page
        tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))
        try:
            next_page = (await (await session.get(url, headers=HEADERS, ssl=USE_SSL)).json()).get('paging', {}).get('next')
        except aiohttp.client_exceptions.ContentTypeError as e:
            raw_content = await response.text()
            print(f"Failed to decode JSON on paging. Raw content was: {raw_content}")
            raise e

    responses = await asyncio.gather(*tasks)
    results = []
    for response in responses:
        try:
            result = await response.json()
            results.append(result)
        except aiohttp.client_exceptions.ContentTypeError as e:
            raw_content = await response.text()
            print(f"Failed to decode JSON in gathered response. Raw content was: {raw_content}")
            raise e

    final_result = {
        'session_infos': [session_info for item in results for session_info in item['session_infos']]
    }
    return final_result



# Verify that "Evict" command should proceed
def sanity_check(session_count):
    while True:
        print(f"You are about to evict {session_count} sessions from share {share_to_evict}")
        response = input(f"Are you sure you want to proceed? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            print(f"Operation cancelled. Exiting")
            sys.exit()
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

# Evict and List function
async def evict_sessions(session, sessions, evict, session_count, who_am_i):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/close"
    print(f"\nCluster: {CLUSTER_ADDRESS}     API Token User: {who_am_i}\n")
    if not evict:
        print(f"Listing {session_count} session(s): {share_to_evict}\n")
        for session_info in sessions:
            print(f"{session_info['user']['name']} is connected to share(s) {', '.join(map(str, session_info['share_names']))} from host {session_info['originator']}")
    else:
        print(f"Evicting {session_count} sessions")
        tasks = []
        for session_info in sessions:
            tasks.append(session.post(url, headers=HEADERS, json=[session_info], ssl=USE_SSL))
            if verbose:
                print(f"Closing session for user {session_info['user']['name']} connected via host {session_info['originator']}")

        responses = await asyncio.gather(*tasks)
        for response in responses:
            if response.status != 200:
                print(f"Operation failed with code {response.status}")

async def main():

    global share_to_evict
    global TOKEN
    global CLUSTER_ADDRESS
    global USE_SSL
    global HEADERS
    global verbose
    global RBAC

    verbose = False
    evict = False
    proceed = False
    list_all = False
    check_access = False

    RBAC = [ "PRIVILEGE_SMB_SESSION_WRITE", "PRIVILEGE_SMB_SESSION_READ", "PRIVILEGE_SMB_SHARE_READ" ]

    # Parse command line options
    parser = argparse.ArgumentParser(description=(
    "Qumulo SMB Share Evictor - Close all sessions on a specific SMB share.\n\n"
    "Evicting a session will close ALL other sessions on the same Qumulo cluster that a User\n"
    "might have also open.\n\n" 
    "For example: If closing session 'Files' and user is connected to both 'Files' and 'Data' which\n"
    "hosted on same Qumulo Cluster then the 'Data' session will also be closed.\n\n"
    "Please note that this script does not disable the SMB share and active client machines will likely\n"
    "quickly re-establish a new SMB session.\n"
    "Please also note that share names for the --share option are case-sesitive!"),formatter_class=argparse.RawTextHelpFormatter
    )

    main_group = parser.add_mutually_exclusive_group(required=True)

    # List all sessions on all shares:
    main_group.add_argument(
        '--showall', '-a', 
        action='store_true', 
        help='List all open SMB sessions on all shares in the cluster'
    )

    # Get the name of the share to evict
    main_group.add_argument(
        '--share', '-s',
        type=str, 
        help='Name of the SMB share from which to evict users'
    )

    # Optional config file
    parser.add_argument(
        '--config', '-c', 
        type=str, 
        help='Optional cluster config file. Default is <localpath>/smb_share_evictor.conf',
        default="smb_share_evictor.conf"
    )    

    # --verbose option
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='Increase output verbosity during session closing'
    )

    args, remaining_args = parser.parse_known_args()
    
    # Check required extra options for --share
    if args.share:

        sub_parser = argparse.ArgumentParser(description="Additional options required for --share")
        # Create group of mutually exclusive -a, -l and -E options
        share_group = sub_parser.add_mutually_exclusive_group(required=True)

        # List Sessions option
        share_group.add_argument(
            '--list', '-l', 
            action='store_true', 
            help='List open sessions on the SMB share designated by the --share/-s argument'
        )

        # Evict Sessions option
        share_group.add_argument(
            '--evict', '-E', 
            action='store_true', 
            help='Evict all sessions on the SMB share designated by the --share/-s argument'
        )

        sub_args = sub_parser.parse_args(remaining_args)
        
        # Merge the secondary arguments into the primary args namespace
        args = argparse.Namespace(**vars(args), **vars(sub_args))

    # Set verbose mode
    if args.verbose:
        verbose = True
    
    # Collect the Share Name
    if args.share:
        share_to_evict = args.share
    
        # Evict sessions if True
        if args.evict:
            evict = True
        
        # Only list specific Share's sessions
        elif args.list:
            evict = False

    # List all sessions
    if args.showall:
        evict = False
        list_all = True
        share_to_evict = ""

    # Check for optional config file
    if args.config:
        config_file = args.config

    # Load config
    config = configparser.ConfigParser()

    # Check that config file exists
    if not os.path.isfile(config_file):
        print(f"ERROR - Config file '{config_file}' not found! Exiting")
        sys.exit()    

    config.read(config_file)

    # Populate info from config file
    CLUSTER_ADDRESS, TOKEN, USE_SSL = config_check(config)
    HEADERS = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Check for access to cluster at CLUSTER_ADDRESS
    if not check_cluster_connectivity(CLUSTER_ADDRESS):
        print(f"Cannot access cluster {CLUSTER_ADDRESS} on port 443. Exiting...")
        sys.exit()

    # Disable verify SSL if set to False
    if not USE_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Check RBAC access level    
    all_privileges, missing_privileges, who_am_i = check_access_rights()
    if not all_privileges:
        print(f"Cannot proceed, user {who_am_i} is missign the following RBAC privileges: {missing_privileges}")
        exit()

    # Main async 'session' function
    async with aiohttp.ClientSession() as session:
        smb_sessions = await get_smb_sessions(session)
        session_infos = [entry for entry in smb_sessions['session_infos']]


        if not list_all:
            # Filter list to only include the desired share to close since "share_names" is a dict and
            # can contain multiple entries
            filtered_list = [
                # {**item, "share_names": [share for share in item["share_names"] if share == share_to_evict]}
                {**item, "share_names": [share for share in item["share_names"]]}
                for item in session_infos
                if share_to_evict in item.get("share_names", [])
            ]
            # Handle empty lists
            if not filtered_list:
                print(f"Share {share_to_evict} does not have any open sessions or does not exist.  Exiting...")
                sys.exit()
        
        # Send all results for --showall
        else:
            filtered_list = session_infos

        # Count user sessions
        session_count = sum('user' in item for item in filtered_list)

        if evict:
            # Ensure user wants to proceed
            proceed = sanity_check(session_count)
        if proceed and evict:
            # Evict sessions if sanity check passes and --evict arg is used
            await evict_sessions(session, filtered_list, evict, session_count, who_am_i)
        elif not evict and not list_all:
            # Run the listing operation only
            await evict_sessions(session, filtered_list, evict, session_count, who_am_i)
        else:
            # Show all sessions
            await evict_sessions(session, session_infos, evict, session_count, who_am_i)

if __name__ == "__main__":
    asyncio.run(main())