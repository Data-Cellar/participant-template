#\‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
#\        ____              __                   ____            ___    ___                           |
#\       /\  _`\           /\ \__               /\  _`\         /\_ \  /\_ \                          |
#\       \ \ \/\ \     __  \ \ ,_\    __        \ \ \/\_\     __\//\ \ \//\ \      __     _ __        |
#\        \ \ \ \ \  /'__`\ \ \ \/  /'__`\       \ \ \/_/_  /'__`\\ \ \  \ \ \   /'__`\  /\`'__\      |
#\         \ \ \_\ \/\ \L\.\_\ \ \_/\ \L\.\_      \ \ \L\ \/\  __/ \_\ \_ \_\ \_/\ \L\.\_\ \ \/       |
#\          \ \____/\ \__/.\_\\ \__\ \__/.\_\      \ \____/\ \____\/\____\/\____\ \__/.\_\\ \_\       |
#\           \/___/  \/__/\/_/ \/__/\/__/\/_/       \/___/  \/____/\/____/\/____/\/__/\/_/ \/_/       |
#\                                                                                                    |
#\            Credentilas Manager API                                                                 |
#\            Radhouene AZZABI <radhouene.azzabi@cea.fr                                               |
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
from libs.crypto.utils import create_proof, verify_credential

from loguru import logger
_logger = logger

# entry point                                                                              
app = FastAPI(title="Data Cellar - Credentials Manager API", root_path="/api/v1")

security = HTTPBearer()


WALLET_API_BASE_URL = os.getenv('WALLET_API_BASE_URL')
DID_WEB_DOMAIN = os.getenv('DID_WEB_DOMAIN')
DATACELLAR_API_BASE_URL = os.getenv('DATACELLAR_API_BASE_URL')
ISSUER_API_KEY = os.getenv('ISSUER_API_KEY')

wallet_kwargs = {
    "wallet_api_base_url": WALLET_API_BASE_URL,
    "did_web_domain": DID_WEB_DOMAIN
}


#---------------------------------------------
# Wallet
#---------------------------------------------

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


@app.get("/dids", dependencies=[Depends(verify_token)], tags=["DIDs"])
def get_dids(request: Request):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    dids = user_wallet.find_did_by_alias(alias="datacellar")
    return dids

@app.post("/dids/create/web", dependencies=[Depends(verify_token)], tags=["DIDs"])
def create_did(request: Request):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    did = user_wallet.create_did_web(alias="datacellar", gx_compliance=True)
    did_document = user_wallet.get_did_document(did=did)
    return { "did" : did_document }

@app.delete("/dids/{did}", dependencies=[Depends(verify_token)], tags=["DIDs"])
def delete_did(did:str, request: Request):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    user_wallet.delete_did_document(did=did)
    return { "did" : did }



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

@app.post("/credentials/useOfferRequest", dependencies=[Depends(verify_token)], tags=["Credential exchange"])
def accept_credential_offer(request: Request, did: str, credential_offer_url = str):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    uuid_str = str(uuid.uuid4())
    try:
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)        
        
        if (not signed_vc):
            raise _logger.warning(f"Error Credentials OfferUrl {e}")
        
        return signed_vc
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")


class FieldFilter(BaseModel):
    type: str
    pattern: Optional[str] = None

class FieldDescriptor(BaseModel):
    path: List[str]
    filter: FieldFilter

class Constraints(BaseModel):
    fields: List[FieldDescriptor]

class InputDescriptor(BaseModel):
    id: str
    format: Optional[Dict[str, Dict[str, List[str]]]] = None 
    constraints: Constraints

class PresentationDefinition(BaseModel):
    id: Optional[str] = None
    input_descriptors: List[InputDescriptor]
    

@app.post("/credentials/matchCredentialsForPresentationDefinition", dependencies=[Depends(verify_token)], tags=["Credential exchange"])
def match_credentials_for_presentation_definition(request: Request, presentation_definition: PresentationDefinition):
    wallet_token = get_wallet_token(request)
    user_wallet = WalletClass(**{**wallet_kwargs, "token":wallet_token})
    presentation_definition_dict = presentation_definition.dict(exclude_none=True)
    try:
        vcs = user_wallet.match_credentials(presentation_definition=presentation_definition_dict)                
        return vcs
    except Exception as e:
        _logger.warning(f"Error Credentials OfferUrl {e}")


#---------------------------------------------
# VC & VP issuing
#---------------------------------------------


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
    
    headers = {"X-API-KEY": ISSUER_API_KEY}

    if not ISSUER_API_KEY:
        _logger.error("Missing or invalid ISSUER_API_KEY, checks it in env var")
        raise HTTPException(status_code=500, detail="")
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str)        
        
        if (not signed_vc):
            raise _logger.warning(f"Error Credentials OfferUrl {e}")
        
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
    
    headers = {"X-API-KEY": ISSUER_API_KEY}

    if not ISSUER_API_KEY:
        _logger.error("Missing or invalid ISSUER_API_KEY, checks it in env var")
        raise HTTPException(status_code=500, detail="")

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()    
        credential_offer_url = response.json()["credential_offer_url"] 
        signed_vc = user_wallet.accept_credential_offer(did=did , credential_offer_url=credential_offer_url, uuid_str=uuid_str) 
        
        if (not signed_vc):
            raise _logger.warning(f"Error Credentials OfferUrl {e}")
        
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
    
    headers = {"X-API-KEY": ISSUER_API_KEY}
    if not ISSUER_API_KEY:
        _logger.error("Missing or invalid ISSUER_API_KEY, checks it in env var")
        raise HTTPException(status_code=500, detail="") 
    
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
        response = requests.post(url, headers=headers, params=params, json=payload)
        response.raise_for_status()

        # Extract credential_offer_url from response JSON
        credential_offer_url = response.json().get("credential_offer_url")
        if not credential_offer_url:
            raise ValueError("Missing 'credential_offer_url' in response.")

        # Accept the credential offer with the user wallet
        signed_vc = user_wallet.accept_credential_offer(did=data.did, credential_offer_url=credential_offer_url, uuid_str=uuid_str)

        if not signed_vc:
            _logger.warning(f"Error: Could not sign the credential for UUID {uuid_str}.")
            raise ValueError(f"Failed to sign the credential for UUID {uuid_str}.")

        # Save signed credential to file
        with open(f"/credentials/vc/{uuid_str}.json", "w") as f:
            f.write(json.dumps(signed_vc, indent=4))

        return signed_vc

    # Handle HTTP and network-related errors
    except requests.exceptions.RequestException as e:
        _logger.error(f"HTTP request failed: {e}")
        raise  # Re-raise the exception after logging

    # Handle JSON decoding errors
    except json.JSONDecodeError as e:
        _logger.error(f"Failed to parse JSON response: {e}")
        raise  # Re-raise after logging

    # Handle any other exception
    except Exception as e:
        _logger.error(f"An error occurred: {e}")
        raise  # Re-raise after logging






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
        presentation["id"] = f"https://{DID_WEB_DOMAIN}/vp/{uuid_str}.json"
    
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
    
    headers = {"X-API-KEY": ISSUER_API_KEY}

    if not ISSUER_API_KEY:
        _logger.error("Missing or invalid ISSUER_API_KEY, checks it in env var")
        raise HTTPException(status_code=500, detail="")
    
        
    try:
        response = requests.post(url, headers=headers, params=params, json=presentation)
        response.raise_for_status()
        
        # Extract credential_offer_url from response JSON
        credential_offer_url = response.json().get("credential_offer_url")
        if not credential_offer_url:
            raise requests.exceptions.HTTPError(
                "Missing 'credential_offer_url' in response.", 
                response=response
            )

        # Accept the credential offer with the user wallet
        signed_vc = user_wallet.accept_credential_offer(did=did, credential_offer_url=credential_offer_url, uuid_str=uuid_str)

        if not signed_vc:
            _logger.warning(f"Error: Could not sign the presentation UUID {uuid_str}.")
            raise requests.exceptions.HTTPError(
                f"Failed to sign the credential for UUID {uuid_str}.",
                response=response
            )

        # Save signed credential to file
        with open(f"/credentials/vp/{uuid_str}.json", "w") as f:
            f.write(json.dumps(signed_vc, indent=4))

        return signed_vc

    except requests.exceptions.HTTPError as http_err:
        # Handle HTTP errors specifically
        _logger.error(f"HTTP error occurred: {http_err}")
        raise HTTPException(status_code=response.status_code, detail=f"External API error: {str(http_err)}")

    except requests.exceptions.RequestException as req_err:
        # Handle network-related errors (timeout, connection issues, etc.)
        _logger.error(f"Request error occurred: {req_err}")
        raise HTTPException(status_code=503, detail=f"Failed to reach external API: {str(req_err)}")

    except Exception as e:
        # Handle any other unexpected exceptions
        _logger.error(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
    
#---------------------------------------------
# Verifier
#---------------------------------------------

def fetch_verifiable_credential(url: str) -> Dict[str, Any]:
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        _logger.error(f"Error fetching VC document from {url}")
        raise HTTPException(status_code=response.status_code, detail=f'{e}')

def verify_individual_credential(credential: Dict[str, Any], legacy_signature: bool) -> Dict[str, Any]:
    verification_result = verify_credential(credential.copy(), use_legacy_catalogue_signature=legacy_signature)
    return {
        "id": credential.get("id"),
        "verified": verification_result,
        "legacy_catalogue": legacy_signature
    }

def verify_credentials(cred_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    verification_results = []
    for cred in cred_list:
        # Try verifying with the legacy signature first
        verification_results.append(verify_individual_credential(cred, True))
        
        # If not verified, try with the non-legacy signature
        if not verification_results[-1]["verified"]:
            verification_results[-1] = verify_individual_credential(cred, False)
    return verification_results

@app.post("/verifiy/proof", tags=["Verifier"])
def verify_credential_signature(request: Request, vc: Optional[Dict[str, Any]] = None, url: Optional[str] = Query(None)) -> Dict:
    
    if vc is None and url is None:
        _logger.error({"status": "error", "message": "Missing 'vc' and 'url' parameters."})
        raise HTTPException(status_code=400, detail="Missing 'vc' and 'url' parameters.")
    
    verifiable_credential = vc.copy() if vc else fetch_verifiable_credential(url)
    
    vc_type = verifiable_credential.get("type", [])
    
    if not vc_type:
        raise HTTPException(status_code=400, detail="No type found in the verifiable credential.")
    
    if vc_type[0] == "VerifiableCredential":
        verification_results = verify_credentials([verifiable_credential])
        return {
            "status": "success",
            "message": "Credential verified successfully",
            "details": verification_results
        }

    elif vc_type[0] == "VerifiablePresentation":
        if "verifiableCredential" not in verifiable_credential:
            raise HTTPException(status_code=400, detail='No verifiable credentials found in the input')

        credentials = verifiable_credential["verifiableCredential"]
        credentials = [credentials] if isinstance(credentials, dict) else credentials

        verification_results = verify_credentials(credentials)
        all_verified = all(result['verified'] for result in verification_results)
        
        message = "All credentials verified successfully" if all_verified else "Some credentials failed verification"
        return {
            "status": "success" if all_verified else "error",
            "message": message,
            "details": verification_results
        }

    raise HTTPException(status_code=500, detail='Unknown error occurred.')


      

if __name__ == '__main__':
    uvicorn.run('main:app', host="0.0.0.0", port=8080, reload=True)