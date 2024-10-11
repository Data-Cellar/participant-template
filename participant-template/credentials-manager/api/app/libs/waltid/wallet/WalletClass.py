import sys
import os
import json
import logging
import pprint
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Union, Optional
from urllib.parse import quote
import sqlite3
import urllib.parse
import environ
import requests
import sh
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from gaiax.registry import check_x5u_compliance_gx_trustanchor
from crypto.utils import extract_jwt_header_payload

_logger = logging.getLogger(__name__)


OID2ALG = {
    "1.2.840.113549.2.9": "HS256",
    "1.2.840.113549.2.10": "HS384",
    "1.2.840.113549.2.11": "HS512",
    "1.2.840.113549.1.1.11": "RS256",
    "1.2.840.113549.1.1.12": "RS384",
    "1.2.840.113549.1.1.13": "RS512",
    "1.2.840.10045.4.3.2": "ES256",
    "1.2.840.10045.4.3.3": "ES384",
    "1.2.840.10045.4.3.4": "ES512",
    "1.2.840.113549.1.1.10": "PS256"
}

@dataclass
class WalletClass:
    wallet_api_base_url: str
    did_web_domain: Optional[str] = ""
    
    email: Optional[str] = ""
    password: Optional[str] = ""
    token: Optional[str] = ""
    wallet_id: Optional[str] = ""
    
    key_path: Optional[str] = ""
    key_id: Optional[str] = ""
    
    database_path: str = "/waltid/data.db"
               
    def __post_init__(self):
        if (self.email and self.password):
            self.token = self.auth_login_wallet(self.email, self.password)
        
        if (self.token):
            self.wallet_id = self.get_first_wallet_id()
        
        if (self.token and self.wallet_id and not self.key_id and self.key_path):
            self.key_id = self.import_key(key_path=f"{self.key_path}/{self.did_web_domain}.key")
            
        if (self.token and self.wallet_id and not self.key_id and not self.key_path):
            self.key_id = self.load_key(algorithm="RSA")
    
    #-------------------------------------------------------
    # Authentication 
    #-------------------------------------------------------   
    def auth_create_wallet(self, email: str, password: str):
        url = self.wallet_api_base_url + "/wallet-api/auth/register"
        data = {
            "name": email,
            "email": email,
            "password": password,
            "type": "email",
        }

        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
            _logger.info(f"User {email} created")
        except requests.exceptions.HTTPError:
            _logger.warning("User already exists.")
    
    def auth_login_wallet(self, email: str, password: str) -> str:
        self.auth_create_wallet(email, password)
        url = self.wallet_api_base_url + "/wallet-api/auth/login"
        data = {"type": "email", "email": email, "password": password}
        response = requests.post(url, json=data)
        response.raise_for_status()
        res_json = response.json()
        _logger.info(res_json)
        return res_json["token"]

    def delete_user_in_waltiddb_by_email(self, email: str):
        table_name = "accounts"
        conn = None
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            query = f'DELETE FROM {table_name} WHERE email = ?'
            cursor.execute(query, (email,))
            conn.commit()
            if cursor.rowcount == 0:
                _logger.error(f"No user found with the specified email {email}")
            else:
                _logger.info(f"Entry with email '{email}' has been deleted.")

        except sqlite3.Error as e:
            _logger.error(f"An error occurred: {e}")

        finally:
            if conn:
                conn.close()
    #-------------------------------------------------------
    # Wallets Accounts
    #-------------------------------------------------------
    def get_first_wallet_id(self) -> str:
        headers = {"Authorization": "Bearer " + self.token}
        url_accounts = self.wallet_api_base_url + "/wallet-api/wallet/accounts/wallets"
        res_accounts = requests.get(url_accounts, headers=headers)
        res_accounts.raise_for_status()
        res_accounts_json = res_accounts.json()
        _logger.info(res_accounts_json)
        return res_accounts_json["wallets"][0]["id"]

    #-------------------------------------------------------
    # Keys 
    #-------------------------------------------------------
    def list_keys(self) -> List[Dict]:
        url_list_keys = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/keys"
        headers = {"Authorization": "Bearer " + self.token}
        res_list = requests.get(url_list_keys, headers=headers)
        res_list.raise_for_status()
        return res_list.json()
    
    def load_key(self, algorithm:str = "RSA") -> str:
        keys_list = self.list_keys()
        for item in keys_list:
            if item["algorithm"] == algorithm:
                return item["keyId"]["id"]
        
        _logger.error(f"no RSA Key found, Generate a new One")
        key_id = self.generate_key(algorithm=algorithm)
        return key_id 
        
    def generate_key(self, algorithm:str = "RSA") -> str:
        url_generate_key = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/keys/generate"
        headers = {"Authorization": "Bearer " + self.token}
        data = {
            "backend": "jwk",
            "keyType": algorithm
        }
        res_generate_key = requests.post(url_generate_key, headers=headers, json=data)
        try:
            res_generate_key.raise_for_status()
            return _logger.error(res_generate_key.text)
        except:
            _logger.error(res_generate_key.text)
            raise
            
    def import_key(self, jwk_key: Dict[str, Any] = None, key_path: str = "") -> str:      
        if (key_path):
            certs_var = open(f"{self.key_path}/{self.did_web_domain}.crt", 'r').read()
            certs = x509.load_pem_x509_certificates(certs_var.encode('UTF-8'))
            cert = certs[0]
            publickey = jwk.JWK.from_pem(cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            jwk_content = publickey.export(as_dict=True)
            jwk_content['alg'] = OID2ALG[cert.signature_algorithm_oid.dotted_string]
            print("public_key", jwk_content)
            private_key=open(key_path, 'r').read()           
            jwk_key = jwk.JWK.from_pem(private_key.encode('UTF-8'))
        
        key_id = jwk_key["kid"]

        keys_list_before = self.list_keys()
        if any([item["keyId"]["id"] == key_id for item in keys_list_before]):
            _logger.warning(f"Key (kid={key_id}) already exists in the wallet")
            return key_id

        url_import_key = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/keys/import"
        headers = {"Authorization": "Bearer " + self.token}
        res_import_key = requests.post(url_import_key, headers=headers, json=jwk_key)

        try:
            res_import_key.raise_for_status()
        except:
            _logger.error(res_import_key.text)
            raise

        keys_list_after = self.list_keys()
        if not any([item["keyId"]["id"] == key_id for item in keys_list_after]):
            raise RuntimeError("Imported key (kid=%s) not found in the list", key_id)

        _logger.info("Imported key (kid=%s) into wallet: %s", key_id, url_import_key)

        return key_id

    def export_key_jwk(self, key_id: str, loadPrivateKey: bool = False) -> dict:
        headers = {"Authorization": "Bearer " + self.token}
        url_export_key = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/keys/{key_id}/export"
        data = {"format": "JWK", "loadPrivateKey": loadPrivateKey}
        
        res_export_key_jwk = requests.get(url_export_key, headers=headers, params=data)

        try:
            res_export_key_jwk.raise_for_status()
        except:
            _logger.error(res_export_key_jwk.text)
            raise

        key_jwk = res_export_key_jwk.json()
        
        return key_jwk   
    
    #-------------------------------------------------------
    # DID 
    #-------------------------------------------------------
    def list_dids(self) -> List[Dict]:
        url_dids = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/dids"
        headers = {"Authorization": "Bearer " + self.token}
        res_dids = requests.get(url_dids, headers=headers)
        res_dids.raise_for_status()
        dids = res_dids.json()
        return dids

    def create_did_web(self, alias:str = "", gx_compliance : bool = False) -> Dict:
        url_create_did = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/dids/create/web"
        headers = {"Authorization": "Bearer " + self.token}
        params = {"keyId": self.key_id, "domain": self.did_web_domain, "path": "/wallet-api/registry/[random-uuid]"}

        if alias:
            params["alias"] = alias

        res_create_did = requests.post(url_create_did, headers=headers, params=params)

        try:
            res_create_did.raise_for_status()
        except:
            _logger.error(res_create_did.text)
            raise

        did_web = res_create_did.text
        
        if gx_compliance:
           self.update_did_document_to_gx(did=did_web)
        
        _logger.debug("DID web created {did_web}")
        return did_web

    def get_did_document(self, did: str) -> Dict:
        url_did = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/dids/{did}"
        headers = {"Authorization": "Bearer " + self.token}
        res_did = requests.get(url_did, headers=headers)
        res_did.raise_for_status()
        did = res_did.json()
        return did
    
    def find_did_by_alias(self, alias: str) -> List[Dict]:
        url_dids = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/dids"
        headers = {"Authorization": "Bearer " + self.token}
        res_dids = requests.get(url_dids, headers=headers)
        res_dids.raise_for_status()
        dids = res_dids.json()
        return [item for item in dids if item["alias"] == alias]
       
    def db_update_document_by_did(self, did:str , new_did_document:str ) :
        database_path = self.database_path
        conn = None
        
        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            
            update_query = """
            UPDATE wallet_dids
            SET document = ?
            WHERE did = ?
            """
            
            cursor.execute(update_query, (new_did_document, did))
            conn.commit()
            
            _logger.debug(f"DID Document content for DID '{did}' has been updated successfully.")
        
        except sqlite3.Error as error:
            _logger.error(f"Error while updating document content: {error}")
        
        finally:
            if conn:
                conn.close()
                
    def update_did_document_to_gx(self, did:str ):
        
        x5u_uri = f"https://{self.did_web_domain}/.well-known/x5u.pem"
        
        check_x5u_compliance_gx_trustanchor(x5u_uri=x5u_uri)
        
        did_document = self.get_did_document(did=did)
        verificationMethod = did_document["verificationMethod"][0]
        verificationMethod["@context"] = "https://w3id.org/security/suites/jws-2020/v1"
        verificationMethod["publicKeyJwk"]["alg"] = "PS256"
        verificationMethod["publicKeyJwk"]["x5u"] = x5u_uri
        
        did_document["verificationMethod"][0] = verificationMethod
        new_did_document = json.dumps(did_document)
        self.db_update_document_by_did(did=did, new_did_document=new_did_document)
   
    def delete_did_document(self, did:str):
        url_did = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/dids/{did}"
        headers = {"Authorization": "Bearer " + self.token}
        res_dids = requests.delete(url_did, headers={**headers,**{"Accept": "*/*"}})
        
        output_message={
            "202"	: "DID deleted",
            "400"	: "DID notfound or could not be deleted",
            "401"	: "Invalid authentication"
        }
        
        try:
            res_dids.raise_for_status()
            return _logger.info(f"{did} {output_message[f'{res_dids.status_code}']}")
        except:
            _logger.error(f"{did} {output_message[f'{res_dids.status_code}']}")
              
    #-------------------------------------------------------
    # Credentials 
    #-------------------------------------------------------   
    def get_credentials(self) -> List[Dict]:
        url_list_credentials = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/credentials?sortBy=addedOn"
        headers = {"Authorization": "Bearer " + self.token}
        res_list = requests.get(url_list_credentials, headers=headers)
        res_list.raise_for_status()
        credentials = res_list.json()
        for item in credentials:
            d = item["document"]
            header, payload = extract_jwt_header_payload(d)
            item["parsedDocument"] = payload["vc"]
       
        return credentials
    
    def delete_credential(self, credentialId : str, permanent : bool = False):
        url_credential = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/credentials/{urllib.parse.quote(credentialId, safe='')}"
        headers = {"Authorization": "Bearer " + self.token}
        params = {"permanent" : permanent}
        res_credential = requests.delete(url_credential, headers={**headers,**{"Accept": "*/*"}}, params=params)
        
        output_message={
            "202"	: "WalletCredential deleted",
            "400"	: "WalletCredential notfound or could not be deleted",
            "401"	: "Invalid authentication"
        }
        
        try:
            res_credential.raise_for_status()
            return _logger.info(f"{credentialId} {output_message[f'{res_credential.status_code}']}")
        except:
            _logger.error(f"{credentialId} {output_message[f'{res_credential.status_code}']}")
    
    def update_credendial(self, id:str, urn:str):
        database_path = self.database_path
        conn = None
        
        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            
            update_query = """
            UPDATE credentials
            SET id = ?
            WHERE id = ?
            """
            
            cursor.execute(update_query, (urn, id))
            conn.commit()
            
            _logger.debug(f"Credendial'{id}' has been updated successfully.")
        
        except sqlite3.Error as error:
            _logger.error(f"Error while updating credential id: {error}")
        
        finally:
            if conn:
                conn.close()
    
    
    #-------------------------------------------------------
    # Credential exchange
    #-------------------------------------------------------
    def accept_credential_offer(self, did: str, credential_offer_url: str) -> dict:
        url_use_offer_request = self.wallet_api_base_url + f"/wallet-api/wallet/{self.wallet_id}/exchange/useOfferRequest"
        headers = {"Authorization": "Bearer " + self.token}
        
        _logger.info(url_use_offer_request)
        
        res_use_offer_request = requests.post(
            url_use_offer_request,
            headers={**headers, **{"Accept": "*/*", "Content-Type": "text/plain"}},
            params={"did": did},
            data=credential_offer_url,
        )
        _logger.info(res_use_offer_request)
        
        
        try:
            res_use_offer_request.raise_for_status()
            res_use_offer_request_json = res_use_offer_request.json()
            _logger.info(pprint.pformat(res_use_offer_request_json))
            urn = f"urn:uuid:{str(uuid.uuid4())}"
            self.update_credendial(id=res_use_offer_request_json[0]["id"],urn = urn)
            _logger.info(pprint.pformat(res_use_offer_request_json))
            return res_use_offer_request_json 
        except requests.exceptions.HTTPError:
            _logger.error(res_use_offer_request.text)
            raise

           