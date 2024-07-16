#!/usr/bin/env python3
import argparse
import urllib3
import configparser
import sys
import os
# import asyncio
# import aiohttp
import json
import requests

# Modify this if you'd liek to store your config in a different place/name
config_file = "share_disconnect.conf"

# Check that config file exists
if not os.path.isfile(config_file):
    print(f"ERROR - Config file '{config_file}' not found! Exiting")
    sys.exit()

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


def get_smb_shares():
    url = f"https://{CLUSTER_ADDRESS}/api/v3/smb/shares/?populate-trustee-names=true"
    return(requests.get(url, headers=HEADERS, verify=USE_SSL).json())
    
def get_smb_sessions():
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/?limit=1"
    sessions = requests.get(url, headers=HEADERS, verify=USE_SSL).json()
    next_page = sessions['paging'].get('next')
    tasks = []

    # Paging support
    while next_page:
        url = f"https://{CLUSTER_ADDRESS}/api" + next_page
        paged_session = requests.get(url, headers=HEADERS, verify=USE_SSL).json()
        tasks.append(paged_session)
        next_page = paged_session.get('paging', {}).get('next')
    result = {
    'session_infos': [session_info for item in tasks for session_info in item['session_infos']]
    }
    return(result)

# Verify that "Evict" command should proceed
def sanity_check():
    while True:
        print(f"You are about to evict all users from share {share_to_evict}")
        response = input(f"Are you sure you want to proceed? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            print(f"Operation cancelled.  Exiting")
            sys.exit()
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

def evict_sessions(sessions, evict):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/close"

    if not evict:
        print(f"Listing sessions on share {share_to_evict}:")
        for session in sessions:
            print(f"{session['user']['name']} is connected from host {session['originator']}")
    else:
        for session in sessions:
            print(f"I'm straight kicking {session['user']['name']} from host {session['originator']} out of share {share_to_evict}")

def main():

    global share_to_evict
    global TOKEN
    global CLUSTER_ADDRESS
    global USE_SSL
    global HEADERS

    verbose = False
    evict = False
    proceed = False

    # Load config
    config = configparser.ConfigParser()
    config.read(config_file)
    CLUSTER_ADDRESS, TOKEN, USE_SSL = config_check(config)
    HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
    }

    # Parse command line options
    parser = argparse.ArgumentParser()

    # --verbose option
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='increase output verbosity'
    )

    # Get the share name
    parser.add_argument(
        '--share', '-s',
        type=str, 
        required=True,
        help='Input the SMB share name from which to evict users'
    )

    group = parser.add_mutually_exclusive_group(required=True)

    # List Sessions option
    group.add_argument(
        '--list', '-l', 
        action='store_true', 
        help='List open sessions on the SMB share desginated by the --share/-s argument'
    )
    
    # Evict Sessions option
    group.add_argument(
        '--evict', '-E', 
        action='store_true', 
        help='Evict all sessions on the SMB share desginated by the --share/-s argument'
    )

    # Parse the arguments
    args = parser.parse_args()

    # Set verbose mode
    if args.verbose:
        verbose = True
    
    # Collect the Share Name
    if args.share:
        share_to_evict = args.share
    
    # Evict sessions if True
    if args.evict:
        evict = True
    
    # Only list sessions if False
    if args.list:
        evict = False

    # Disable verify SSL if set to False
    if not USE_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Run the main functions
    smb_sessions = get_smb_sessions()
    session_infos = [ entry for entry in smb_sessions['session_infos']]
            
    # Filter list to only include the desired share to close since "share_names" is a dict and
    # can contain multiple entries
    filtered_list = [
    {**item, "share_names": [share for share in item["share_names"] if share == share_to_evict]}
    for item in session_infos
    if share_to_evict in item.get("share_names", [])
    ]
    
    if evict:
        # Ensure user wants to proceed
        proceed = sanity_check()
    if proceed and evict:
        # Evict sessions if sanity check passes and --evict arg is used
        evict_sessions(filtered_list, evict)
    else:
        # Run the listing operation only
        evict_sessions(filtered_list, evict)          


if __name__ == "__main__":
    main()