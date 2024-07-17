#!/usr/bin/env python3
import argparse
import urllib3
import configparser
import sys
import os
import json
import aiohttp
import asyncio

# Modify this if you'd like to store your config in a different place/name
config_file = "smb_share_evictor.conf"

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

async def get_smb_shares(session):
    url = f"https://{CLUSTER_ADDRESS}/api/v3/smb/shares/?populate-trustee-names=true"
    async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
        return await response.json()

async def get_smb_sessions(session):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/?limit=100"
    async with session.get(url, headers=HEADERS, ssl=USE_SSL) as response:
        sessions = await response.json()
    
    next_page = sessions['paging'].get('next')
    tasks = []
    tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))
    # Paging support
    while next_page:
        url = f"https://{CLUSTER_ADDRESS}/api" + next_page
        tasks.append(session.get(url, headers=HEADERS, ssl=USE_SSL))
        next_page = (await (await session.get(url, headers=HEADERS, ssl=USE_SSL)).json()).get('paging', {}).get('next')

    responses = await asyncio.gather(*tasks)
    results = [await response.json() for response in responses]

    result = {
        'session_infos': [session_info for item in results for session_info in item['session_infos']]
    }
    return result

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

async def evict_sessions(session, sessions, evict, session_count):
    url = f"https://{CLUSTER_ADDRESS}/api/v1/smb/sessions/close"

    if not evict:
        print(f"Listing {session_count} sessions on share {share_to_evict}:")
        for session_info in sessions:
            print(f"{session_info['user']['name']} is connected from host {session_info['originator']}")
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
        help='List open sessions on the SMB share designated by the --share/-s argument'
    )
    
    # Evict Sessions option
    group.add_argument(
        '--evict', '-E', 
        action='store_true', 
        help='Evict all sessions on the SMB share designated by the --share/-s argument'
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

    async with aiohttp.ClientSession() as session:
        smb_sessions = await get_smb_sessions(session)
        session_infos = [entry for entry in smb_sessions['session_infos']]
                
        # Filter list to only include the desired share to close since "share_names" is a dict and
        # can contain multiple entries
        filtered_list = [
            {**item, "share_names": [share for share in item["share_names"] if share == share_to_evict]}
            for item in session_infos
            if share_to_evict in item.get("share_names", [])
        ]

        if not filtered_list:
            print(f"Share {share_to_evict} does not have any open sessions or does not exist.  Exiting...")
            sys.exit()

        # Count user sessions
        session_count = sum('user' in item for item in filtered_list)

        if evict:
            # Ensure user wants to proceed
            proceed = sanity_check(session_count)

        if proceed and evict:
            # Evict sessions if sanity check passes and --evict arg is used
            await evict_sessions(session, filtered_list, evict, session_count)
        else:
            # Run the listing operation only
            await evict_sessions(session, filtered_list, evict, session_count)

if __name__ == "__main__":
    asyncio.run(main())
