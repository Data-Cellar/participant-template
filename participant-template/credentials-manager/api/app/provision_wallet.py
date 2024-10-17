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


if __name__ == '__main__':
    wallet_kwargs = {
            "wallet_api_base_url": WALLET_API_BASE_URL,
            "did_web_domain": DID_WEB_DOMAIN,
            "email":WALLET_USER_EMAIL, 
            "password":WALLET_USER_PASSWORD, 
            "key_path":"/certs",
            "force_create": True
        }

    participant_wallet = WalletClass(**wallet_kwargs)
    dids = participant_wallet.find_did_by_alias(alias="datacellar")
    if (not len(dids)):
        participant_did = participant_wallet.create_did_web(alias="datacellar", gx_compliance=True)
    else:
        participant_did = dids[0]["did"]

    _logger.info(f"Prticipant DID ={participant_did}")
    
    did_document = participant_wallet.get_did_document(did=participant_did)
    key_id = did_document["verificationMethod"][0]["publicKeyJwk"]["kid"]
    participant_key_jwk = participant_wallet.export_key_jwk(key_id=key_id, loadPrivateKey = True)

    credentials_ids = participant_wallet.get_credentials()
    for d in [item["id"] for item in credentials_ids]:
        _logger.info(f"credentialId={d}")
        participant_wallet.delete_credential(credentialId=d, permanent=True)
    
    