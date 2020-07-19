import urllib.request
from urllib.parse import quote as urllib_quote
import requests
import os
import logging
import datetime
import base64	
import json
from datetime import datetime, timedelta, timezone

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def encode_creds():
    creds = os.environ['CHECKMARX_USERNAME'] + ':' + os.environ['CHECKMARX_PASSWORD']
    return base64.b64encode(creds.encode("ascii")).decode("ascii")

def get_access_token():
    headers = {
        'Accept': 'application/json;v=1.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'username': os.environ['CHECKMARX_USERNAME'],
        'password': os.environ['CHECKMARX_PASSWORD'],
        'grant_type': 'password',
        'scope': 'sast_rest_api',
        'client_id': 'resource_owner_client',
        'client_secret': os.environ['checkmarx_client_secret']
    }
    resp = requests.post('{URL}/cxrestapi/auth/identity/connect/token', data=payload, headers=headers)
    if resp.status_code == 200:
        return resp.json()['access_token']
    else:
        logging.error(f"Failed to get access_token.  Status Code: {resp.status_code}")
        exit(1)

def get_team_id(token):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    full_team_name = f"\\CxServer\\SP\\Company\\{os.environ['CHECKMARX_TEAM_NAME']}"
    resp = requests.get("{URL}/cxrestapi/auth/teams", headers=headers)
    teams = resp.json()
    for team in teams:
        if team['fullName'] == full_team_name:
            return team['id']
    logging.error(f"Failed to get team id for team name: {os.environ['CHECKMARX_TEAM_NAME']}")
    exit(1)
    
def get_project(token, teamId):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'projectName': os.environ['CHECKMARX_PROJECT_NAME'],
        'teamId': teamId
    }
    resp = requests.get('{URL}/cxrestapi/projects', headers=headers, params=payload)
    if resp.status_code == 200:
        return resp.json()[0]
    else:
        logging.error(f"Failed to get projects. Status Code: {resp.status_code}")
        exit(1)

def get_recent_scans(token, projectid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }
    payload = {
        'projectId': projectid,
        'scanStatus': 'Finished',
        'last': 1
    }
    resp = requests.get('{URL}/cxrestapi/sast/scans',params=payload, headers=headers)

    if resp.status_code == 200:
        return resp.json()
    else:
        logging.error(f"Failed to get recent scans.  Status Code: {resp.status_code}")
        exit(1)

def get_scan_results(token, scanid):
    headers = {
        'Accept': 'application/json;v=1.0',
        'Authorization': f"Bearer {token}"
    }        
    resp = requests.get(f"{URL}/cxrestapi/sast/scans/{scanid}/resultsStatistics", headers=headers)

    if resp.status_code == 200:
        return resp.json()
    else:
        logging.error(f"Failed to get scans results.  Status Code: {resp.status_code}")
        exit(1)

def get_scan_custom(projectid, date):
    headers = {
        "Authorization": "Basic %s" % encode_creds(),
        "Content-Type": "application/json; odata.metadata=minimal",
    }
    filters = f"ProjectId%20eq%20{projectid}%20and%20ScanRequestedOn%20gt%20{date}"
    
    req = urllib.request.Request(f"{URL}/Cxwebinterface/odata/v1/Scans?$filter={filters}&$expand=Results($expand=State;$select=Id,ScanId,StateId)", headers=headers)
    response = urllib.request.urlopen(url=req)    
    json_results = response.read()
    json_obj = json.loads(json_results)
    return json_obj

def get_scan_results(scan):
    headers = {
        "Authorization": "Basic %s" % encode_creds(),
        "Content-Type": "application/json; odata.metadata=minimal",
    }
    
    req = urllib.request.Request(f"{URL}/Cxwebinterface/odata/v1/Scans({scan})/Results", headers=headers)
    response = urllib.request.urlopen(url=req)    
    json_results = response.read()
    json_obj = json.loads(json_results)
    return json_obj

def main():
    configure_logging()
    token = get_access_token()
    teamid = get_team_id(token)
    projects = get_project(token, teamid)

    scaninfo = get_recent_scans(token, projects['id'])

    results = []
    for scan in scaninfo:
        results.append(get_scan_results(scan['id']))

    lowitems = 0
    mediumitems = 0
    highitems = 0
    infoitems = 0
    count = 0

    with open('results.json', 'a') as f:
        f.write('[')
        for result in results[0]['value']:
            if result['StateId'] != 1:
                if count > 0: f.write(",")
                json.dump(result, f)
                count +=1
                
                if result['Severity'] == 'Low': lowitems +=1
                elif result['Severity'] == "Medium": mediumitems +=1
                elif result['Severity'] == "High": highitems +=1
                elif result['Severity'] == "Info": infoitems +=1
        f.write(']')
    
    with open('stats.json', 'a') as f:
        f.write('[{')
        f.write(f"'Info': '{infoitems}', 'Low': '{lowitems}', 'Medium': '{mediumitems}', 'High': '{highitems}'")
        f.write('}]')

if __name__ == "__main__":
    main() 
