#\‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
#\        ____              __                   ____            ___    ___                           |
#\       /\  _`\           /\ \__               /\  _`\         /\_ \  /\_ \                          |
#\       \ \ \/\ \     __  \ \ ,_\    __        \ \ \/\_\     __\//\ \ \//\ \      __     _ __        |
#\        \ \ \ \ \  /'__`\ \ \ \/  /'__`\       \ \ \/_/_  /'__`\\ \ \  \ \ \   /'__`\  /\`'__\      |
#\         \ \ \_\ \/\ \L\.\_\ \ \_/\ \L\.\_      \ \ \L\ \/\  __/ \_\ \_ \_\ \_/\ \L\.\_\ \ \/       |
#\          \ \____/\ \__/.\_\\ \__\ \__/.\_\      \ \____/\ \____\/\____\/\____\ \__/.\_\\ \_\       |
#\           \/___/  \/__/\/_/ \/__/\/__/\/_/       \/___/  \/____/\/____/\/____/\/__/\/_/ \/_/       |
#\                                                                                                    |                                           
#\            credentilas.manager                                                                        |
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

PARTICIPANT_LEGAL_NAME = os.getenv('PARTICIPANT_LEGAL_NAME') or 'CEA'
PARTICIPANT_VAT_ID = os.getenv('PARTICIPANT_VAT_ID') or "FR43775685019"
PARTICIPANT_COUNTRY_SUBDIVISION_CODE = os.getenv('PARTICIPANT_COUNTRY_SUBDIVISION_CODE') or "FR-OCC"

CREDENTIALS_MANAGER_API = "http://localhost:8080/api/v1"

def get_terms_and_conditions(token: str="", did: str=""):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/vc/TermsAndConditions"
    res = requests.post(url, headers=headers, params={"did":did})
    res.raise_for_status()
    signed_vc = res.json()
    return signed_vc

def get_legal_registration_number(token: str="", did: str=""):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/vc/LegalRegistrationNumber"
    res = requests.post(url, headers=headers, params={"did":did, "vatId": PARTICIPANT_VAT_ID})
    res.raise_for_status()
    signed_vc = res.json()
    return signed_vc

def get_legal_participant(token:str = "", did: str="", legalRegistrationNumber: str="", tsandcs: str="", use_legacy_catalogue_signature:bool = False):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/vc/LegalParticipant"
    data={
        "did" : did,
        "legalName" : PARTICIPANT_LEGAL_NAME,
        "countrySubdivisionCode" : PARTICIPANT_COUNTRY_SUBDIVISION_CODE,
        "legalRegistrationNumber" : legalRegistrationNumber,
        "tsandcs" : tsandcs
    }
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature
    }
    
    res = requests.post(url, headers=headers, params=params, json={"did":did})
    res.raise_for_status()
    signed_vc = res.json()
    return signed_vc

def vp_self_sign(token:str = "",vcs=[], did:str = "", use_legacy_catalogue_signature:bool = False):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/vp/self_sign"
    data={
        "id" : "",
        "verifiableCredential" : vcs
    }
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature,
        "did": did
    }
    res = requests.post(url, headers=headers, params=params, json=data)
    res.raise_for_status()
    signed_vc = res.json()
    return signed_vc
    
def vp_issuer_sign(token:str = "", vcs=[], did:str = "", use_legacy_catalogue_signature:bool = False):
    headers = {"Authorization": "Bearer " + token}
    url = CREDENTIALS_MANAGER_API+ "/vp/issuer_sign"
    data={
        "id" : "",
        "verifiableCredential" : vcs
    }
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature,
        "did": did
    }
    
    res = requests.post(url, headers=headers, params=params, json=data)
    res.raise_for_status()
    signed_vc = res.json()
    return signed_vc 



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
    
    _logger.info("[Issuer Signed VC] -> terms_and_conditions")
    tsandcs  = get_terms_and_conditions(token=wallet_token, did=did)
    _logger.info(tsandcs["id"])

    _logger.info("[Issuer Signed VC] -> legal_registration_number")
    lrn = get_legal_registration_number(token=wallet_token, did=did)
    _logger.info(tsandcs["id"])

    _logger.info("[Issuer Signed VC] -> legal_participant")
    lp = get_legal_participant(token=wallet_token, did=did, legalRegistrationNumber = lrn["id"], tsandcs=tsandcs["id"], use_legacy_catalogue_signature=True)
    _logger.info(lp["id"])

    _logger.info("[Self Signed VP] -> legal_participant")
    vp_lp_ss= vp_self_sign(token=wallet_token, did=did, vcs = [lp],use_legacy_catalogue_signature=True)
    _logger.info(vp_lp_ss["id"])

    _logger.info("[Issuer Signed VP] -> Legal_participant")
    vp_lp_is= vp_issuer_sign(token=wallet_token, did=did, vcs = [lp], use_legacy_catalogue_signature=True)
    _logger.info(vp_lp_is["id"])