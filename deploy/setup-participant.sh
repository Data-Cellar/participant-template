#!/usr/bin/env bash

# Default values
DEFAULT_PARTICIPANT_NAME="consumer"
DEFAULT_DOMAIN_NAME="datacellar.cosypoc.ovh"
DEFAULT_PARTICIPANT_ROOT_FOLDER="$USER_WORKING_DIR/participants"
DEFAULT_PROXY_FOLDER="$USER_WORKING_DIR/reverse-proxy/caddy"
DEFAULT_USE_LETSENCRYPT="true"
DEFAULT_DATACELLAR_IDP_URL="https://idp.datacellar.cosypoc.ovh"
DEFAULT_ISSUER_DID="did:web:idp.datacellar.cosypoc.ovh:wallet-api:registry:01c06d48-6174-4323-a007-bd8af6d5b0c5"
DEFAULT_ISSUER_API_KEY="0164ca06-e718-49c5-8eb9-46e4a3fe1531"

# Function to prompt for input with a default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    read -p "$prompt [$default]: " input
    eval "$var_name=\${input:-$default}"
}

# Prompt for inputs
prompt_with_default "Enter Participant Name" "$DEFAULT_PARTICIPANT_NAME" participant_name
prompt_with_default "Enter Domain Name" "$DEFAULT_DOMAIN_NAME" domain_name
prompt_with_default "Enter Participant Folder" "$DEFAULT_PARTICIPANT_ROOT_FOLDER" participant_root_folder
prompt_with_default "Enter proxy folder" "$DEFAULT_PROXY_FOLDER" proxy_folder
prompt_with_default "Use Let's Encrypt? (true/false)" "$DEFAULT_USE_LETSENCRYPT" use_letsencrypt
prompt_with_default "Set DATACELLAR_IDP_URL" "$DEFAULT_DATACELLAR_IDP_URL" datacellar_idp_url
prompt_with_default "Set ISSUER_API_BASE_URL" "$datacellar_idp_url" issuer_api_url
prompt_with_default "Set ISSUER_DID" "$DEFAULT_ISSUER_DID" issuer_did
prompt_with_default "Set ISSUER_API_KEY" "$DEFAULT_ISSUER_API_KEY" issuer_api_key
prompt_with_default "Set VERIFIER_API_BASE_URL" "$datacellar_idp_url" verifier_api_url

# Set environment variables
export PARTICIPANT_ROOT_FOLDER="$participant_root_folder"
export PARTICIPANT_NAME="$participant_name"
export DOMAIN_NAME="$domain_name"
export PROXY_FOLDER="$proxy_folder"
export USE_LETSENCRYPT="$use_letsencrypt"
export DATACELLAR_IDP_URL="$datacellar_idp_url"
export ISSUER_API_BASE_URL="$issuer_api_url"
export ISSUER_DID="$issuer_did"
export ISSUER_API_KEY="$issuer_api_key"
export VERIFIER_API_BASE_URL="$verifier_api_url"

# Construct paths and other derived variables
PARTICIPANT_FOLDER="$PARTICIPANT_ROOT_FOLDER/$PARTICIPANT_NAME"
PARTICIPANT_TEMPLATE="$USER_WORKING_DIR/../participant-template/"
EXTERNAL_PROXY_FOLDER="$PROXY_FOLDER"
PROXY_CERT_FOLDER="$PROXY_FOLDER/certs"

# Export derived variables
export PARTICIPANT_FOLDER PARTICIPANT_TEMPLATE EXTERNAL_PROXY_FOLDER PROXY_CERT_FOLDER

# Display setup information
echo "--------------------------------------------------------"
echo "Setting up Datacellar participant"
echo "--------------------------------------------------------"
echo "Name: $PARTICIPANT_NAME"
echo "Folder: $PARTICIPANT_FOLDER"
echo "Domain: $DOMAIN_NAME"
echo "Proxy folder: $PROXY_FOLDER"
echo "Using Let's Encrypt: $USE_LETSENCRYPT"

# Execute commands
if [ -d "$PARTICIPANT_FOLDER" ]; then
    (cd "$PARTICIPANT_FOLDER" && task stop-all) || echo "Failed to stop participant"
    sudo rm -R "$PARTICIPANT_FOLDER" || echo "Failed to remove participant folder"
fi

mkdir -p "$PARTICIPANT_FOLDER"
cp -R "$PARTICIPANT_TEMPLATE"/* "$PARTICIPANT_FOLDER/"
envsubst <"$PARTICIPANT_TEMPLATE/.env.tmpl" >"$PARTICIPANT_FOLDER/.env"

(cd "$PARTICIPANT_FOLDER" && task config-all)
cp "$PARTICIPANT_FOLDER/reverse-proxy/caddy/conf.d/$PARTICIPANT_NAME.caddy" "$EXTERNAL_PROXY_FOLDER/conf.d/$PARTICIPANT_NAME.caddy"
docker compose -f "$EXTERNAL_PROXY_FOLDER/../docker-compose.yml" restart caddy
