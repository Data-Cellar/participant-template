import json
import logging
import requests
import uuid
from typing import Any, Dict, List, Tuple, Union

_logger = logging.getLogger(__name__)


def gx_compliance(vp: Dict[str,any], vcId: str = "") -> dict :
    url="https://compliance.lab.gaia-x.eu/v1-staging/api/credential-offers"
    
    if (vcId):
        url += f"?vcid={vcId}"
        
    response = requests.post(url, json=vp)
    try:
        response.raise_for_status()
        signed_cred = response.json()
           
        return signed_cred

    except requests.exceptions.HTTPError:
        _logger.error("Unable to submit to compliance")
        _logger.error(response.text)
        