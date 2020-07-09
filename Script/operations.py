import requests
import os
import logging
import datetime
import base64	
import json
import sys
import time

def configure_logging():
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def _set_headers(username: str = None, api_key: str = None):
    headers = {'Content-Type': 'application/json'}
    if username: headers['Authorization'] = f'Basic {username}'
    if api_key: headers['Authorization'] = f'Bearer {api_key}'

    return headers

def process_api_request(url: str, verb: str, headers: dict, data: dict = None, params: dict = None):
    try:
        if data: r = getattr(requests, verb.lower())(url,headers=headers,data=json.dumps(data))
        elif params: r = getattr(requests, verb.lower())(url,headers=headers,params=json.dumps(params))
        else: r = getattr(requests, verb.lower())(url,headers=headers)

        r.raise_for_status()
    except Exception as e:
        logging.error(f'An error occured executing the API call: {e}')

    try:
        return r.json()
    except Exception as e:
        logging.error(f'An error occured loading the content: {e}')
        return None

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
    resp = requests.post('https://{SAST_URL}/cxrestapi/auth/identity/connect/token', data=payload, headers=headers)
    if resp.status_code == 200:
        return resp.json()['access_token']
    else:
        logging.error(f"Failed to get access_token.  Status Code: {resp.status_code}")
        sys.exit(1)

def get_dr_status(token, requestid):
    status = process_api_request(f'https://q2ebanking.checkmarx.net/cxrestapi/sast/dataRetention/{requestid}/status', 'GET', _set_headers(api_key=token))
    
    if (status['stage']['value'] == 'Finished'): 
        return False
    else:
        return True
    
def start_dr(token, scanstokeep):
    data = {
        'numOfSuccessfulScansToPreserve' : scanstokeep
    }
    return process_api_request('https://{SAST_URL}/cxrestapi/sast/dataRetention/byNumberOfScans', 'POST', _set_headers(api_key=token), data=data)

def main():
    configure_logging()
    token = get_access_token()
    
    requestid = start_dr(token, os.environ['CHECKMARX_DR'])['id']
    logging.info(f"Starting Data Rention Process. Keeping {os.environ['CHECKMARX_DR']} scan(s)")
    
    while get_dr_status(token, requestid):
        time.sleep(30)
        logging.info("Waiting for Data Rention process to complete...")

    logging.info(f"Finished Data Rention Process. RequestID: {requestid}")

if __name__ == "__main__":
    main()