#\‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
#\        ____              __                   ____            ___    ___                           |
#\       /\  _`\           /\ \__               /\  _`\         /\_ \  /\_ \                          |
#\       \ \ \/\ \     __  \ \ ,_\    __        \ \ \/\_\     __\//\ \ \//\ \      __     _ __        |
#\        \ \ \ \ \  /'__`\ \ \ \/  /'__`\       \ \ \/_/_  /'__`\\ \ \  \ \ \   /'__`\  /\`'__\      |
#\         \ \ \_\ \/\ \L\.\_\ \ \_/\ \L\.\_      \ \ \L\ \/\  __/ \_\ \_ \_\ \_/\ \L\.\_\ \ \/       |
#\          \ \____/\ \__/.\_\\ \__\ \__/.\_\      \ \____/\ \____\/\____\/\____\ \__/.\_\\ \_\       |
#\           \/___/  \/__/\/_/ \/__/\/__/\/_/       \/___/  \/____/\/____/\/____/\/__/\/_/ \/_/       |
#\                                                                                                    |
#\            Create Legal Participant Script                                                         |
#\            Radhouene AZZABI <radhouene.azzabi@cea.fr                                               |
#\____________________________________________________________________________________________________|

import uvicorn
import os
import json
import logging
from colorlog import ColoredFormatter
import coloredlogs
import pprint
import requests
import string
import uuid
from jwt import PyJWKClient
import jwt

from pydantic import BaseModel
from typing import Dict, List, Tuple, Union, Annotated, Optional, Any
from urllib.parse import quote, urlparse, parse_qs

from libs.waltid.wallet import WalletClass

from loguru import logger
_logger = logger

#---------------------------------------
# Provision Wallet For Admin 
#--------------------------------------- 
WALLET_API_BASE_URL = os.getenv('WALLET_API_BASE_URL')
WALLET_USER_NAME = os.getenv('WALLET_USER_NAME')
WALLET_USER_EMAIL = os.getenv('WALLET_USER_EMAIL')
WALLET_USER_PASSWORD = os.getenv('WALLET_USER_PASSWORD')
DID_WEB_DOMAIN = os.getenv('DID_WEB_DOMAIN')

LEGAL_PARTICIPANT_ID = os.getenv('LEGAL_PARTICIPANT_ID') 


CREDENTIALS_MANAGER_API = "http://localhost:8080/api/v1"

def register_participant_to_catalogue(token: str="", legal_participant_id: str=""):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/catalogue/participant/register"
    try:
        response = requests.post(url, headers=headers, params={"url":legal_participant_id})
        response.raise_for_status()
        response_json = response.json()
        return response_json
    
    except requests.exceptions.HTTPError as http_err:
        _logger.error(f"{http_err}")
        return
         
    except requests.exceptions.RequestException as req_err:
        _logger.error(f"Failed to register particiapnt into catalogue: {req_err}")
        return 

    except Exception as e:
        _logger.error(f"An error occurred: {e}")
        return 

if __name__ == '__main__':
    wallet_kwargs = {
            "wallet_api_base_url": WALLET_API_BASE_URL,
            "did_web_domain": DID_WEB_DOMAIN,
            "email":WALLET_USER_EMAIL, 
            "password":WALLET_USER_PASSWORD, 
        }

    participant_wallet = WalletClass(**wallet_kwargs)
    wallet_token = participant_wallet.token   
    dids = participant_wallet.find_did_by_alias(alias="datacellar")
    did = dids[0]["did"]
    _logger.info(f"[Participant DID] -> {did}")
        
    _logger.info("[Global Catalogue] -> register legal participant")
    _logger.info(f"[LEGAL_PARTICIPANT_ID] -> {LEGAL_PARTICIPANT_ID}")
    register_legal_participant  = register_participant_to_catalogue(token=wallet_token, legal_participant_id=LEGAL_PARTICIPANT_ID)
    if (not register_legal_participant):
        _logger.error("failed to register legal participant")
        exit(1) 
    _logger.info(register_legal_participant)