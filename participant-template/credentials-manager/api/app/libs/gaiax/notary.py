import json
import logging
import requests
from jwcrypto import jwk, jws
from typing import Any, Dict, List, Tuple, Union
from datetime import datetime, timedelta
_logger = logging.getLogger(__name__)

#-----------------------------------------------------------
# Gaia-X Get Registration-number
# OpenAPI Spec : https://registrationnumber.notary.lab.gaia-x.eu/main/docs#/
#-----------------------------------------------------------

def get_verification_key_from_notary():
    cert_url = "https://registrationnumber.notary.lab.gaia-x.eu/main/x509CertificateChain.pem"
    reg_cert_response = requests.get(cert_url)
    if reg_cert_response.status_code != 200:
        raise Exception(
            f"Unable to retrieve verification certificate "
            f"from: {cert_url}"
        )
    verification_cert_pem = reg_cert_response.text.encode('UTF-8')
    verification_key = jwk.JWK.from_pem(verification_cert_pem)
    return verification_key    

def get_registration_number_vc_v2(vcId : str, vatId : str  ) -> Dict[str, any]:
    base_url = f"https://registrationnumber.notary.lab.gaia-x.eu/v1/registrationNumberVC"
    headers = {'content-type' : 'application/json'}
    params={
        "vcid" : vcId
    }
    data = {
        "@context": [
            "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant"
        ],
        "type": "gx:legalRegistrationNumber",
        "id": vcId,
        "gx:vatID": vatId
    }
    response = requests.post(base_url, headers=headers, params=params, data=json.dumps(data))
    
    try:
        response.raise_for_status()
        res_json = response.json()
        return res_json
        
    except:
        _logger.error(response.text)
        _logger.error("Error requesting a legalRegistrationNumber from Gaia-X Notary:")
        raise
         
def get_registration_number_vc(vcId : str, subjectId: str, vatId : str  = False, leiCode:str = False, eori:str = False, taxId:str = False) -> Dict[str, any]:
    base_url = "https://registrationnumber.notary.lab.gaia-x.eu/main/registration-numbers"
    endpoint_map = {
        "vat-id": vatId,
        "lei-code": leiCode,
        "eori": eori,
        "tax-id": taxId
    }

    # Find the first valid endpoint
    for endpoint, identifier in endpoint_map.items():
        if identifier:
            url = f"{base_url}/{endpoint}/{identifier}"
            break
    else:
        url = None

    if url:
        data = {"vcId": vcId, "subjectId": subjectId}
        try:
            response = requests.get(url, params=data)
            response.raise_for_status()
            jws_token = response.text
            try:
                jws_obj = jws.JWS()
                jws_obj.deserialize(jws_token)
                jwk_key = get_verification_key_from_notary()
                jws_obj.verify(jwk_key)
                payload = jws_obj.payload
                data = json.loads(payload)
                
                created = datetime.utcnow().isoformat() + 'Z'
                proof = {
                    "type": "JsonWebSignature2020",
                    "created" : created,
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:web:registrationnumber.notary.lab.gaia-x.eu:main#X509-JWK",
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://w3id.org/security/suites/jws-2020/v1"
                    ],
                    "jws": jws_token,
                }
                data['proof'] = proof
                return data
            except Exception as e:
                print(f"Error: {e}")
        except requests.exceptions.HTTPError as err:
            _logger.error("Error requesting a Registration Number VC from Gaia-X Notary: %s", err)
