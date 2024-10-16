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
from jwcrypto.jws import JWK, JWS

from pydantic import BaseModel
from typing import Dict, List, Tuple, Union, Annotated, Optional, Any
from urllib.parse import quote, urlparse, parse_qs

from fastapi import FastAPI, HTTPException, Depends, Security, Request, status, Query                    
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


from libs.waltid.wallet import WalletClass
from libs.crypto.utils import create_proof

from loguru import logger
_logger = logger

# entry point                                                                              
app = FastAPI(title="Data Cellar - Credentials Manager API", root_path="/api/v1")

security = HTTPBearer()


WALLET_API_BASE_URL = os.getenv('WALLET_API_BASE_URL')
DID_WEB_DOMAIN = os.getenv('DID_WEB_DOMAIN')
DATACELLAR_API_BASE_URL = os.getenv('DATACELLAR_API_BASE_URL')


wallet_kwargs = {
    "wallet_api_base_url": WALLET_API_BASE_URL,
    "did_web_domain": DID_WEB_DOMAIN
}


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        test_wallet = WalletClass(**{**wallet_kwargs, "token":token})
        test_wallet.get_first_wallet_id()
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"Authorization": "Bearer"},
        )

def get_wallet_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        wallet_token = auth_header.split("Bearer ")[1]
        return wallet_token
    else:
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")


class WalletLogin(BaseModel): ## models
    email: str = "admin@datacellar.com"
    password : str = "admin_d@t@ce!!ar"
    
@app.post("/login", tags=["Auth"])
def login(request: Request, data: WalletLogin):
    user_wallet = WalletClass(**{**wallet_kwargs, "email":data.email, "password":data.password})
    return { "token" : user_wallet.token}

@app.get("/dids", dependencies=[Depends(verify_token)], tags=["DID"])
def get_dids(request: Request):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    dids = user_wallet.find_did_by_alias(alias="datacellar")
    return dids

@app.get("/credentials", dependencies=[Depends(verify_token)], tags=["Credentials"])
def get_credentials(request: Request):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    credentials = user_wallet.get_credentials()
    return credentials

@app.get("/credentials/{credentialId}", dependencies=[Depends(verify_token)], tags=["Credentials"])
def view_credential(request: Request, credentialId:str):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    credential = user_wallet.get_credential(credentialId=credentialId)
    return credential

@app.delete("/credentials/{credentialId}", dependencies=[Depends(verify_token)], tags=["Credentials"])
def delete_credential(request: Request, credentialId:str):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    user_wallet.delete_credential(credentialId=credentialId, permanent=True)
    return { "credentialId" : credentialId }

@app.post("/credentials/useOfferRequest", dependencies=[Depends(verify_token)], tags=["Credentials"])
def accept_credential_offer(request: Request, did: str, credential_offer_url = str):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    uuid_str = str(uuid.uuid4())
    try:
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)        
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")


@app.post("/vc/TermsAndConditions", dependencies=[Depends(verify_token)], tags=["DataCellar"])
def get_terms_and_conditions(request: Request, did: str):
    
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    
    url = DATACELLAR_API_BASE_URL + "/issuer/vc/TermsAndConditions"
    uuid_str = str(uuid.uuid4())
    data = {
        "id": f"https://{DID_WEB_DOMAIN}/vc/{uuid_str}.json",
        "did": did
    }
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)        
        
        with open(f"/credentials/vc/{uuid_str}.json", "w") as f:
            f.write(json.dumps( signed_vc, indent=4))
            
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")

@app.post("/vc/LegalRegistrationNumber", dependencies=[Depends(verify_token)], tags=["DataCellar"])
def get_legal_registration_number(request: Request, did: str, vatId: str = "FR43775685019"):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    
    url = DATACELLAR_API_BASE_URL + "/issuer/vc/LegalRegistrationNumber"
    uuid_str = str(uuid.uuid4())
    data = {
        "id": f"https://{DID_WEB_DOMAIN}/vc/{uuid_str}.json",
        "vatId": vatId
    }
    print(data)
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str) 
        
        with open(f"/credentials/vc/{uuid_str}.json", "w") as f:
            f.write(json.dumps( signed_vc, indent=4))
                   
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")

class VCLegalParticipant(BaseModel): ##models
    did: str = ""
    legalName: str = ""
    countrySubdivisionCode: str = ""
    legalRegistrationNumber: str = ""
    tsandcs: str = ""
    
@app.post("/vc/LegalParticipant", dependencies=[Depends(verify_token)], tags=["DataCellar"])
def get_legal_participant(request: Request, data: VCLegalParticipant, use_legacy_catalogue_signature: bool = Query(False, description="Set to true to use legacy catalogue signature")):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    
    url = f"{DATACELLAR_API_BASE_URL}/issuer/vc/LegalParticipant"
    headers={"Accept": "application/json"}  
    
    uuid_str = str(uuid.uuid4())
    payload = {
        "id" : f"https://{DID_WEB_DOMAIN}/vc/{uuid_str}.json",
        "did" : data.did,
        "legalName" : data.legalName,
        "countrySubdivisionCode" : data.countrySubdivisionCode,
        "legalRegistrationNumber" : data.legalRegistrationNumber,
        "tsandcs" : data.tsandcs
    }
    
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature
    }
    
    try:
        response = requests.post(url, params=params, json=payload)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=data.did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)
        
        with open(f"/credentials/vc/{uuid_str}.json", "w") as f:
            f.write(json.dumps( signed_vc, indent=4))
                    
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")

class VPDatacellar(BaseModel): ##models
    id: str = ""
    verifiableCredential: List[Dict[str, Any]] = []
    
@app.post("/vp/self_sign", dependencies=[Depends(verify_token)], tags=["DataCellar"])
def vp_self_sign(request: Request, vp: VPDatacellar, did:str, use_legacy_catalogue_signature: bool = Query(False, description="Set to true to use legacy catalogue signature")):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    
    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": vp.id,
        "verifiableCredential": vp.verifiableCredential,
    }
    
    uuid_str = str(uuid.uuid4())
    if (not presentation["id"]):
        presentation["id"] = f"https://{DID_WEB_DOMAIN}/vc/{uuid_str}.json"
    
    did_document = user_wallet.get_did_document(did=did)
    key_id = did_document["verificationMethod"][0]["publicKeyJwk"]["kid"]
    jwk_key = user_wallet.export_key_jwk(key_id=key_id, loadPrivateKey = True)
    signature_jwk = JWK(**jwk_key)  
    
    verification_method=f"{did}#{jwk_key['kid']}"
    
    vp_payload = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": presentation["verifiableCredential"],
    }
       
    try:
        proof = create_proof(credential=vp_payload, signature_jwk=signature_jwk, verification_method=verification_method, use_legacy_catalogue_signature=use_legacy_catalogue_signature)
        presentation['proof'] = proof
        
        with open(f"/credentials/vp/{uuid_str}.json", "w") as f:
            f.write(json.dumps( presentation, indent=4))
        
        return presentation
    except Exception as e:
        _logger.warning(f"Error vp selfsigning {e}")


@app.post("/vp/issuer_sign", dependencies=[Depends(verify_token)], tags=["DataCellar"])
def vp_issuer_sign(request: Request, vp: VPDatacellar, did:str, use_legacy_catalogue_signature: bool = Query(False, description="Set to true to use legacy catalogue signature")):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    
    presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": vp.id,
        "verifiableCredential": vp.verifiableCredential,
    }
    
    uuid_str = str(uuid.uuid4())
    if (not presentation["id"]):
        presentation["id"] = f"https://{DID_WEB_DOMAIN}/vp/{uuid_str}.json"
    
    url = f"{DATACELLAR_API_BASE_URL}/issuer/vp/sign"
    headers={"Accept": "application/json"} 
    params={
        "use_legacy_catalogue_signature": use_legacy_catalogue_signature
    }
    
    headers = {"X-API-KEY": "0164ca06-e718-49c5-8eb9-46e4a3fe1531"}
    try:
        response = requests.post(url, headers=headers, params=params, json=presentation)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)        
        with open(f"/credentials/vp/{uuid_str}.json", "w") as f:
            f.write(json.dumps( presentation, indent=4))
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error VP Issuer Sign  {e}") 
        raise e
       

if __name__ == '__main__':
    uvicorn.run('main:app', host="0.0.0.0", port=8080, reload=False)