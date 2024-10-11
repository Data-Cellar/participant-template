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
import pprint
import requests
import string
import uuid
from jwt import PyJWKClient
import jwt

from pydantic import BaseModel
from typing import Dict, List, Tuple, Union, Annotated, Optional, Any
from urllib.parse import quote, urlparse, parse_qs

from fastapi import FastAPI, HTTPException, Depends, Security, Request, status, Query                    

from libs.waltid.wallet import WalletClass

# entry point                                                                              
app = FastAPI(title="Data Cellar - Credentials Manager API", root_path="/api/v1")

#---------------------------------------
# Provision Wallet For Admin 
#--------------------------------------- 
WALLET_API_BASE_URL = os.getenv('WALLET_API_BASE_URL')
WALLET_USER_NAME = os.getenv('WALLET_USER_NAME')
WALLET_USER_EMAIL = os.getenv('WALLET_USER_EMAIL')
WALLET_USER_PASSWORD = os.getenv('WALLET_USER_PASSWORD')
DID_WEB_DOMAIN = os.getenv('DID_WEB_DOMAIN')

kwargs = {
        "wallet_api_base_url": WALLET_API_BASE_URL,
        "email": WALLET_USER_EMAIL,
        "password": WALLET_USER_PASSWORD,
        "key_path" : "/certs",
        "did_web_domain": DID_WEB_DOMAIN
    }

participant_wallet = WalletClass(**kwargs)
dids = participant_wallet.find_did_by_alias(alias="datacellar")
if (not len(dids)):
    participant_did = participant_wallet.create_did_web(alias="datacellar", gx_compliance=True)
else:
    participant_did = dids[0]["did"]

print(f"participant_did: {participant_did}")
anchor_did_document = participant_wallet.get_did_document(did=participant_did)

print(f"anchor_did_document")
print(anchor_did_document)


if __name__ == '__main__':
    uvicorn.run('main:app', host="0.0.0.0", port=8080, reload=False)