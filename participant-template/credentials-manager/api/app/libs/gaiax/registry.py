import json
import logging
import requests
from typing import Any, Dict, List, Tuple, Union

from loguru import logger as _logger

def check_x5u_compliance_gx_trustanchor(x5u_uri: str) -> dict :
    url = "https://registry.lab.gaia-x.eu/v1-staging/api/trustAnchor/chain/file"
    data = {"uri": x5u_uri}
    response = requests.post(url, json=data)
    try:
        response.raise_for_status()
        res_json = response.json()
        _logger.info("Root for the certificate chain is verified as a TrustAnchor in the registry")
        return res_json["result"]
    
    except requests.exceptions.HTTPError:
        _logger.error("Root for the certificate chain could not be verified as a TrustAnchor in the registry")
        _logger.info("may be you need to append Root Chain to your x5u eg. curl -s https://letsencrypt.org/certs/isrgrootx1.pem | tee -a /webdid/x5u.pem")
        #raise




    