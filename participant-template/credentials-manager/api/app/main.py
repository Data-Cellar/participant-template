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
from uvicorn.supervisors.watchgodreload import CustomWatcher
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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


# entry point                                                                              
app = FastAPI(title="Data Cellar - Credentials Manager API", root_path="/api/v1")


if __name__ == '__main__':
    uvicorn.run('main:app', host="0.0.0.0", port=8080, reload=False)