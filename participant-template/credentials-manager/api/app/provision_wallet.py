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

logging.basicConfig(level=logging.INFO)
_logger = logging.getLogger(__name__)




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

#ISSUER_API_BASE_URL = os.getenv('ISSUER_API_BASE_URL') or 'https://idp.datacellar.cosypoc.ovh/api/v1'
ISSUER_API_BASE_URL = 'https://idp.datacellar.cosypoc.ovh/api/v1'
CREDENTIALS_MANAGER_API = "http://localhost:8080/api/v1"


wallet_kwargs = {
        "wallet_api_base_url": WALLET_API_BASE_URL,
        "did_web_domain": DID_WEB_DOMAIN,
        "email":WALLET_USER_EMAIL, 
        "password":WALLET_USER_PASSWORD, 
        "key_path":"/certs"
    }

participant_wallet = WalletClass(**wallet_kwargs)
dids = participant_wallet.find_did_by_alias(alias="datacellar")
if (not len(dids)):
    participant_did = participant_wallet.create_did_web(alias="datacellar", gx_compliance=True)
else:
    participant_did = dids[0]["did"]

did_document = participant_wallet.get_did_document(did=participant_did)
key_id = did_document["verificationMethod"][0]["publicKeyJwk"]["kid"]
participant_key_jwk = participant_wallet.export_key_jwk(key_id=key_id, loadPrivateKey = True)


credentials_ids = participant_wallet.get_credentials()
for d in [item["id"] for item in credentials_ids]:
    print(f"credentialId={d}")
    participant_wallet.delete_credential(credentialId=d, permanent=True)



def get_terms_and_conditions():
    headers = {"Authorization": "Bearer " + participant_wallet.token}
    url = CREDENTIALS_MANAGER_API+ "/vc/TermsAndConditions"
    res = requests.post(url, headers=headers, params={"did":participant_did})
    res.raise_for_status()
    signed_vc = res.json()
    _logger.info(signed_vc)
    return signed_vc

def get_legal_registration_number():
    headers = {"Authorization": "Bearer " + participant_wallet.token}
    url = CREDENTIALS_MANAGER_API+ "/vc/LegalRegistrationNumber"
    res = requests.post(url, headers=headers, params={"did":participant_did, "vatId": PARTICIPANT_VAT_ID})
    res.raise_for_status()
    signed_vc = res.json()
    _logger.info(signed_vc)
    return signed_vc

def get_legal_participant(legalRegistrationNumber: str, tsandcs: str, use_legacy_catalogue_signature:bool = False):
    headers = {"Authorization": "Bearer " + participant_wallet.token}
    url = CREDENTIALS_MANAGER_API+ "/vc/LegalParticipant"
    data={
        "did" : participant_did,
        "legalName" : PARTICIPANT_LEGAL_NAME,
        "countrySubdivisionCode" : PARTICIPANT_COUNTRY_SUBDIVISION_CODE,
        "legalRegistrationNumber" : legalRegistrationNumber,
        "tsandcs" : tsandcs
    }
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature
    }
    
    res = requests.post(url, headers=headers, params=params, json={"did":participant_did})
    res.raise_for_status()
    signed_vc = res.json()
    _logger.info(signed_vc)
    return signed_vc

def vp_selfsigned(vcs=[], did:str = "", use_legacy_catalogue_signature:bool = False):
    headers = {"Authorization": "Bearer " + participant_wallet.token}
    url = CREDENTIALS_MANAGER_API+ "/vp/selfsigned"
    data={
        "id" : ""
        "verifiableCredential" : vcs
    }
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature,
        "did": did
    }
    res = requests.post(url, headers=headers, params=params, json=data)
    res.raise_for_status()
    signed_vc = res.json()
    _logger.info(signed_vc)
    return signed_vc
    
     

print("get_terms_and_conditions")
tsandcs  = get_terms_and_conditions()

print("get_legal_registration_number")
lrn = get_legal_registration_number()

print("get_legal_registration_number")
lp = get_legal_participant(legalRegistrationNumber = lrn["id"], tsandcs=tsandcs["id"])

print("selfsigned_vp")
vp_lp_ss= vp_selfsigned(vcs = [tsandcs, lrn, lp], did=participant_did)