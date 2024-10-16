
import os
from datetime import datetime, timedelta, timezone
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json
from hashlib import sha256
import requests
import jcs
from jwcrypto import jws
from jwcrypto.jws import JWK, JWS
from jwcrypto.common import json_encode
from pyld import jsonld
from typing import Dict, List, Tuple, Union, Annotated

# The base URL for the Universal Resolver hosted by DIF
UNIVERSAL_RESOLVER_URL = os.getenv('UNIVERSAL_RESOLVER_URL') or "https://uniresolver.io/1.0/identifiers/"


def timenow(days=0):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def compact_token(token):
    parts = token.split(".")
    return parts[0] + ".." + parts[2]


def normalize(doc):
    return jsonld.normalize(doc, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})


def sha256_normalized_vc(normalized_vc):
    return sha256(normalized_vc.encode('utf-8'))


def sha256_string(canonized_vc):
    return sha256(canonized_vc).hexdigest()

def canonicalize(doc):
    return jcs.canonicalize(doc)


def sign_doc(doc, signature_jwk, issuer_verification_method):
    
    signing_algorithm = "PS256"
    
    # URDNA normalize
    normalized = normalize(doc)
    # sha256 the RDF
    normalized_hash = sha256_normalized_vc(normalized)
    # Sign using JWS
    hashed_signature_payload = normalized_hash.hexdigest()
    print("hashed_signature_payload F1")
    print(hashed_signature_payload)
    
    
    # In the following the actual signing process takes place Important info: The following headers must have
    # this exact format (which is defined in the related Specification)
    jws_protected_header = '{"b64":false,"crit":["b64"],"alg":"%s"}' % signing_algorithm
    jws_token = jws.JWS(hashed_signature_payload)
    #  Important info: Internally, the signer uses the following input for the signing process:
    #  signing_input = encoded_jws_protected_header + b'.' + hashed_signature_payload
    jws_token.add_signature(
        signature_jwk, protected=jws_protected_header, alg=signing_algorithm)
        
    signed = jws_token.serialize(compact=True)
    
    doc['proof'] = {
        "type": "JsonWebSignature2020",
        "proofPurpose": "assertionMethod",
        "verificationMethod": issuer_verification_method,
        "jws": compact_token(signed)
    }
    return doc

#https://github.com/GAIA-X4PLC-AAD/self-description-creator/blob/main/src/self_description_processor.py#L12
def create_proof(credential: dict, signature_jwk: JWK, verification_method: str, use_legacy_catalogue_signature: bool=False) -> dict:
        
    """
    Sign a Credential with `JSON Web Signature 2020`. Relevant information can be found in the related Specification
    (see https://www.w3.org/TR/vc-jws-2020/#proof-representation).
    :param credential: The credential where a Proof will be added to
    :return: The Credential including a Proof
    """
    signing_algorithm = "PS256"
    
    proof = {
        "type": "JsonWebSignature2020",
        "created": timenow(0),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    }
    # Important info (legacy catalogue): The @context provided in the proof object is required to successfully perform the
    # normalization with the used pyld library. This is what the corresponding Java implementation does as well,
    # but with API version 'v3', instead of 'v3-unstable'. But the 'v3' just returns a HTTP 404. Not sure at the
    # moment, why it works with the Java implementation. The actual proof fields don't need this context.
    proof_for_normalization = proof.copy()
    proof_for_normalization["@context"] = "https://w3id.org/security/v3-unstable"
    # The content to be signed must be converted into a canonical JSON representation to ensure that the
    # verification of the signature on different systems leads to the same results
    normalization_options = {
        "algorithm": "URDNA2015",
        "format": "application/n-quads"}
    
    canonical_proof = jsonld.normalize(
        proof_for_normalization, options=normalization_options)
    hashed_proof = sha256(canonical_proof.encode('utf-8')).hexdigest()
    
    canonical_credential = jsonld.normalize(
        credential, options=normalization_options)
       
    hashed_credential = sha256(
        canonical_credential.encode('utf-8')).hexdigest()

    hashed_signature_payload = hashed_credential
    if use_legacy_catalogue_signature:
        hashed_signature_payload = bytes.fromhex(
            hashed_proof + hashed_credential)
    
    # In the following the actual signing process takes place Important info: The following headers must have
    # this exact format (which is defined in the related Specification)
    jws_protected_header = '{"b64":false,"crit":["b64"],"alg":"%s"}' % signing_algorithm
    jws_token = jws.JWS(hashed_signature_payload)
    #  Important info: Internally, the signer uses the following input for the signing process:
    #  signing_input = encoded_jws_protected_header + b'.' + hashed_signature_payload
        
    jws_token.add_signature(
        signature_jwk, protected=jws_protected_header, alg=signing_algorithm)
    
    # According to W3C Json Web Signature for Data Integrity Proof (
    # https://www.w3.org/TR/vc-jws-2020/#proof-representation) for proof type 'JsonWebSignature2020' the jws
    # property MUST contain a detached JWS which omits the actual payload
    b64_encoded_header = base64url_encode(jws_token.objects["protected"])
    b64_encoded_signature = base64url_encode(
        jws_token.objects["signature"])
    detached_jws_string = b64_encoded_header + '..' + b64_encoded_signature
       
    proof["jws"] = detached_jws_string
    
    return proof

def verify_proof(credential: dict, proof: dict, verification_key: JWK, use_legacy_catalogue_signature: bool = False) -> bool:
    """
    Verify a proof attached to a credential using the JWS signature verification method.
    
    :param credential: The credential that contains the proof
    :param proof: The proof object that contains the JWS signature
    :param verification_key: The public JWK key used to verify the signature
    :param use_legacy_catalogue_signature: Flag to specify if the legacy catalog signature format should be used
    :return: True if the verification is successful, False otherwise
    """
    signing_algorithm = "PS256"

    # Extract the JWS from the proof
    jws_string = proof.get("jws", None)
    if not jws_string:
        raise ValueError("No JWS token found in the proof.")

    # Split the detached JWS string into header and signature parts
    try:
        header_b64, signature_b64 = jws_string.split("..")
    except ValueError:
        raise ValueError("Invalid JWS format.")

    # Decode the header and signature
    jws_header = base64url_decode(header_b64)
    signature = base64url_decode(signature_b64)

    # Prepare the content to be verified (credential and proof normalization)
    proof_for_normalization = proof.copy()
    proof_for_normalization.pop("jws")  # Remove the jws before normalization
    proof_for_normalization["@context"] = "https://w3id.org/security/v3-unstable"

    normalization_options = {
        "algorithm": "URDNA2015",
        "format": "application/n-quads"
    }

    # Canonicalize and hash the proof
    canonical_proof = jsonld.normalize(
        proof_for_normalization, options=normalization_options)
    hashed_proof = sha256(canonical_proof.encode('utf-8')).hexdigest()

    # Canonicalize and hash the credential
    canonical_credential = jsonld.normalize(
        credential, options=normalization_options)
    hashed_credential = sha256(
        canonical_credential.encode('utf-8')).hexdigest()

    # Combine the hashes based on the legacy flag
    hashed_signature_payload = hashed_credential
    if use_legacy_catalogue_signature:
        hashed_signature_payload = bytes.fromhex(
            hashed_proof + hashed_credential)

    # Recreate the signing input as per the JWS specification
    #signing_input = header_b64.encode('utf-8') + b'.' + hashed_signature_payload

    # Verify the signature using the provided public JWK
    jws_token = jws.JWS()
    jws_token.deserialize(jws_string)
    try:
        jws_token.verify(
                verification_key,
                detached_payload=hashed_signature_payload
            )
        print("Credential Verification Successful")
        return True
    except jws.InvalidJWSSignature:
        print("Credential Verification Failed")
        return False




def fetch_did_document(did : str) -> Dict[str,any] :
    url = UNIVERSAL_RESOLVER_URL + did
    try:
        response = requests.get(url)
        response.raise_for_status()
                
        did_document = response.json()
        print(f"Resolved DID Document for {did}:")
        return did_document["didDocument"]

    except Exception as e:
        raise Exception(f"Error fetching DID document for {did}: {e}")
        

def fetch_public_key(did : str, verificationMethod: str) -> Dict[str, any]:
    try:
        
        did_document = fetch_did_document(did)
        verification_method = next(
            (method for method in did_document["verificationMethod"] if method['id'] == verificationMethod), 
            None
        )
        print(f"Verification method for public key ID '{verificationMethod}':", verificationMethod)

        if not verification_method:
            raise Exception(f"Public key with id {verificationMethod} not found in DID document")

        if verification_method['type'] != "JsonWebKey2020":
            raise Exception(f"Unsupported key type: {verification_method['type']}")

        public_key_jwk = verification_method['publicKeyJwk']
        
        return public_key_jwk

    except Exception as error:
        raise Exception("Error fetching public key:", error)
      
   
def verify_credential(verifiable_credential: Dict[str, any], use_legacy_catalogue_signature : bool=False):
        
        proof = verifiable_credential.pop("proof")       
        verificationMethod = proof["verificationMethod"]
        did = verificationMethod.split('#')[0]
        try:
            publicKeyJwk = fetch_public_key(did=did, verificationMethod=verificationMethod)
        except Exception as e:
            raise Exception(f"verificationMethod failed: {e}")
             
        
        verification_key = JWK(**publicKeyJwk)       

        return verify_proof(credential=verifiable_credential, proof=proof, verification_key=verification_key,  use_legacy_catalogue_signature=use_legacy_catalogue_signature)
        
def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')


def base64url_decode(payload: str) -> bytes:
    # Add padding if necessary. Base64 requires the string to be padded to a multiple of 4.
    padding = 4 - (len(payload) % 4)
    if padding != 4:
        payload += '=' * padding
    return urlsafe_b64decode(payload)


def _base64url_decode(input_str):
    # Add padding if necessary to make it a valid base64 string
    input_str += '=' * (4 - len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str).decode('utf-8')

def extract_jwt_header_payload(jwt_token):
    # Split the JWT token into header, payload, and signature
    header_b64, payload_b64, _ = jwt_token.split('.')

    # Decode the header and payload from Base64URL
    header = json.loads(_base64url_decode(header_b64))
    payload = json.loads(_base64url_decode(payload_b64))

    return header, payload