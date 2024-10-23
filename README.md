# dc-participant

This repository contains all the essential components needed to set up a DataCellar participant. It includes a web server for hosting verifiable credentials, a participant wallet, the EDC connector, and the CDE. These tools are designed to facilitate secure and efficient data exchange within the DataCellar dataspace.

## Project Structure

```
├── deploy
│   ├── participants
│   ├── reverse-proxy
│   └── taskfile.yml
├── install
│   ├── install_docker.sh
│   └── install_taskfile.sh
├── LICENSE
├── participant-template
│   ├── cde
│   ├── credentials-manager
│   ├── did-server
│   ├── edc-connector
│   ├── reverse-proxy
│   ├── scripts
│   ├── store
│   ├── wallet
│   ├── .env.tmpl
│   └── taskfile.yml
├── README.md
```

The `participant-template` directory contains all the necessary modules to create a participant. All component configurations are defined in the `.env.tmpl` file.

The `deploy` directory contains the script used to create a participant. It uses **Taskfile** and includes a single task: `setup-participant`.

### Available Tasks

```yaml
task: Available tasks for this project:
   * create-legalparticipant:                                       Create Legal Participant
   * cde:config:                                                    Config DID Server
   * cde:start:                                                     Start DID Server
   * cde:stop:                                                      Stop DID Server
   * connector:config:                                              Config Connector
   * connector:run-examples:                                        Runs the Consumer Pull/Push example script from the consumer
   * connector:start:                                               Start Connector
   * connector:start-consumer:                                      Start Connector Consumer
   * connector:start-provider:                                      Start Connector Provider
   * connector:stop:                                                Stop Connector
   * credentials-manager:create-legalparticipant:                   Create a legal participant with provided legalname, vatid, and country_subdivision_code
   * credentials-manager:provision-wallet:                          Provision Wallet
   * credentials-manager:register-legalparticipant-catalogue:       Register a legal participant to the global catalogue
   * credentials-manager:start-api:                                 Start Credentials Manager API
   * credentials-manager:stop-api:                                  Stop Credentials Manager
   * did-server:config:                                             Config DID Server
   * did-server:start:                                              Start DID Server
   * did-server:stop:                                               Stop DID Server
   * proxy:restart:                                                 Restart Reverse Proxy
   * proxy:start:                                                   Start Reverse Proxy
   * proxy:stop:                                                    Stop Reverse Proxy
   * wallet:config:                                                 Config Wallet
   * wallet:start:                                                  Start Wallet
   * wallet:stop:                                                   Stop Wallet
```

## Deploy a New Participant

To deploy a new participant, navigate to the `deploy` directory and use the `task setup-participant` command.

### Prerequisites

Before deploying a participant, ensure that Docker and Taskfile are installed. Navigate to the `install` directory and run the following commands:

```bash
$ sudo ./install_docker.sh 
$ sudo ./install_taskfile.sh 
```

### Steps to Deploy a Consumer Participant

In this example, we will assume that the participant is named **consumer**.

1. Navigate to the `deploy` directory:

   ```bash
   cd deploy
   ```

2. Run the task to set up the participant:

   ```bash
   task setup-participant
   ```

3. Follow the prompts to provide the required information, such as:
   - Participant Name 
   - Domain Name
   - Participant Folder
   - Proxy Folder
   - Let's Encrypt usage
   - `DATACELLAR_IDP_URL`
   - `ISSUER_API_BASE_URL`
   - `ISSUER_DID`
   - `ISSUER_API_KEY`
   - `VERIFIER_API_BASE_URL`

    > **Note**: The environment variables will be set according to your inputs. Ensure that the configuration is correct before proceeding. The setup process will create a new participant in the specified folder and configure it.

    > If a participant folder already exists, the script will stop all services and delete the folder before creating a new one. Ensure that the folder and proxy paths you provide are correct and accessible.

4. Once configured, navigate to the participant directory and start all services:

   ```bash
   cd participant/consumer  
   task start-all
   ```
   > the wallet will be configured and provisioned at the startup time, 
   > a did web document will be generated and stored in the wallet 

   You will be prompted to confirm whether you want to generate a legal Participant VC. If you choose "yes," provide the following details:
   - **Legal Name**
   - **VAT ID** (A valid VAT ID is required)
   - **Country Subdivision Code** (A valid country subdivision code is required)

   The system will use the OpenID4VC protocol to request the following Verifiable Credentials (VCs) from the Datacellar Issuer:
   - Terms and Conditions
   - Legal Registration Number
   - Legal Participant

   > **Tip**: You can rerun this step later by executing the **task credentials-manager:create-legalparticipant**.

   Afterward, you will be asked whether you want to start a connector. Choose **consumer** when prompted to select the connector type.

### Steps to Deploy a Provider Participant

Repeat the steps above, but this time, use **provider** as the participant name and select the **provider** connector type.

## Running Examples

Once both the consumer and provider connectors are running, you can test data exchange between them. In a new terminal, navigate to the **consumer** directory and run the following task:

```bash
task connector:run-examples
```

You will be prompted to choose a test type (Pull/Push or Catalogue). For the `counter_party_id`, enter **provider**, and for the `counter_party_url`, leave the default value.

you need to see this log
<details>
<summary>console output</summary>

```console
debian@vps-79d2c53f:~/datacellar/dc-participant/deploy/participants/consumer$ task connector:run-examples
Run examples (pull/push/catalogue) [catalogue]: 
Set counter_party_connector_id (provider): 
Set COUNTER_PARTY_PROTOCOL_URL (https://provider.datacellar.cosypoc.ovh/protocol): 
2024-10-23 00:55:08 c034b11ec33a asyncio[8] DEBUG Using selector: EpollSelector
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CERT_PATH'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_RABBIT_URL'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_HTTP_API_PORT'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_SCHEME'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_HOST'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_CONNECTOR_ID'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_PARTICIPANT_ID'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_MANAGEMENT_PORT'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_MANAGEMENT_PATH'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_CONTROL_PORT'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_CONTROL_PATH'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_PUBLIC_PORT'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_PUBLIC_PATH'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_PROTOCOL_PORT'.
2024-10-23 00:55:08 c034b11ec33a environ_config[8] DEBUG looking for env var 'EDC_CONNECTOR_PROTOCOL_PATH'.
2024-10-23 00:55:08 c034b11ec33a __main__[8] DEBUG Configuration:
AppConfig(cert_path='/opt/src/config/certs/consumer.datacellar.cosypoc.ovh.crt', rabbit_url='amqp://guest:guest@consumer.connector-broker:5672', http_api_port=8000, connector=AppConfig.Connector(scheme='http', host='consumer.connector', connector_id='consumer', participant_id='consumer', management_port=9193, management_path='/management', control_port=9192, control_path='/control', public_port=9291, public_path='/public', protocol_port=9194, protocol_path='/protocol'))
2024-10-23 00:55:08 c034b11ec33a httpx[8] DEBUG load_ssl_context verify=True cert=None trust_env=True http2=False
2024-10-23 00:55:08 c034b11ec33a httpx[8] DEBUG load_verify_locations cafile='/usr/local/lib/python3.8/dist-packages/certifi/cacert.pem'
2024-10-23 00:55:08 c034b11ec33a edcpy.edc_api[8] DEBUG -> POST http://consumer.connector:9193/management/v2/catalog/request
{'@context': {'@vocab': 'https://w3id.org/edc/v0.0.1/ns/'},
 'counterPartyAddress': 'https://provider.datacellar.cosypoc.ovh/protocol',
 'protocol': 'dataspace-protocol-http'}
2024-10-23 00:55:08 c034b11ec33a httpcore.connection[8] DEBUG connect_tcp.started host='consumer.connector' port=9193 local_address=None timeout=60 socket_options=None
2024-10-23 00:55:08 c034b11ec33a httpcore.connection[8] DEBUG connect_tcp.complete return_value=<httpcore._backends.anyio.AnyIOStream object at 0x7f53652fe850>
2024-10-23 00:55:08 c034b11ec33a httpcore.http11[8] DEBUG send_request_headers.started request=<Request [b'POST']>
2024-10-23 00:55:08 c034b11ec33a httpcore.http11[8] DEBUG send_request_headers.complete
2024-10-23 00:55:08 c034b11ec33a httpcore.http11[8] DEBUG send_request_body.started request=<Request [b'POST']>
2024-10-23 00:55:08 c034b11ec33a httpcore.http11[8] DEBUG send_request_body.complete
2024-10-23 00:55:08 c034b11ec33a httpcore.http11[8] DEBUG receive_response_headers.started request=<Request [b'POST']>
2024-10-23 00:55:13 c034b11ec33a httpcore.http11[8] DEBUG receive_response_headers.complete return_value=(b'HTTP/1.1', 200, b'OK', [(b'Date', b'Wed, 23 Oct 2024 00:55:08 GMT'), (b'Content-Type', b'application/json'), (b'Content-Length', b'2904')])
2024-10-23 00:55:13 c034b11ec33a httpx[8] INFO HTTP Request: POST http://consumer.connector:9193/management/v2/catalog/request "HTTP/1.1 200 OK"
2024-10-23 00:55:13 c034b11ec33a httpcore.http11[8] DEBUG receive_response_body.started request=<Request [b'POST']>
2024-10-23 00:55:13 c034b11ec33a httpcore.http11[8] DEBUG receive_response_body.complete
2024-10-23 00:55:13 c034b11ec33a httpcore.http11[8] DEBUG response_closed.started
2024-10-23 00:55:13 c034b11ec33a httpcore.http11[8] DEBUG response_closed.complete
2024-10-23 00:55:13 c034b11ec33a edcpy.edc_api[8] DEBUG <- POST http://consumer.connector:9193/management/v2/catalog/request
{'@context': {'@vocab': 'https://w3id.org/edc/v0.0.1/ns/',
              'dcat': 'http://www.w3.org/ns/dcat#',
              'dct': 'http://purl.org/dc/terms/',
              'dspace': 'https://w3id.org/dspace/v0.8/',
              'edc': 'https://w3id.org/edc/v0.0.1/ns/',
              'odrl': 'http://www.w3.org/ns/odrl/2/'},
 '@id': 'd2dd5254-fdad-4178-83fe-6bd5c0532448',
 '@type': 'dcat:Catalog',
 'dcat:dataset': [{'@id': 'POST-consumption-prediction',
                   '@type': 'dcat:Dataset',
                   'dcat:distribution': [{'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpProxy-PUSH'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PULL'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PUSH'}}],
                   'id': 'POST-consumption-prediction',
                   'name': 'POST /consumption/prediction '
                           '(run_consumption_prediction_consumption_prediction_post)',
                   'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtUE9TVC1jb25zdW1wdGlvbi1wcmVkaWN0aW9u:UE9TVC1jb25zdW1wdGlvbi1wcmVkaWN0aW9u:NzhkNDJkZGItZGYxOS00MGYxLTgzNDItMGVjZTM1ZWU1MGNi',
                                      '@type': 'odrl:Offer',
                                      'odrl:obligation': [],
                                      'odrl:permission': [],
                                      'odrl:prohibition': []}},
                  {'@id': 'POST-dummy',
                   '@type': 'dcat:Dataset',
                   'dcat:distribution': [{'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpProxy-PUSH'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PULL'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PUSH'}}],
                   'id': 'POST-dummy',
                   'name': 'POST /dummy (process_data_dummy_post)',
                   'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtUE9TVC1kdW1teQ==:UE9TVC1kdW1teQ==:ZTJiMTI1YzgtZGQ0Mi00YjlhLTlmMTUtYzNiMzRjNjk0YzNm',
                                      '@type': 'odrl:Offer',
                                      'odrl:obligation': [],
                                      'odrl:permission': [],
                                      'odrl:prohibition': []}},
                  {'@id': 'GET-consumption',
                   '@type': 'dcat:Dataset',
                   'dcat:distribution': [{'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpProxy-PUSH'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PULL'}},
                                         {'@type': 'dcat:Distribution',
                                          'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                                          'dct:format': {'@id': 'HttpData-PUSH'}}],
                   'id': 'GET-consumption',
                   'name': 'GET /consumption '
                           '(get_consumption_data_consumption_get)',
                   'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtR0VULWNvbnN1bXB0aW9u:R0VULWNvbnN1bXB0aW9u:OWIyNjA1YzctZTAzMi00NWE5LThhMDYtNzcwMWMxNDNjMTBk',
                                      '@type': 'odrl:Offer',
                                      'odrl:obligation': [],
                                      'odrl:permission': [],
                                      'odrl:prohibition': []}}],
 'dcat:service': {'@id': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                  '@type': 'dcat:DataService',
                  'dct:endpointUrl': 'https://provider.datacellar.cosypoc.ovh/protocol',
                  'dct:terms': 'connector'},
 'dspace:participantId': 'provider',
 'participantId': 'provider'}
2024-10-23 00:55:13 c034b11ec33a httpcore.connection[8] DEBUG close.started
2024-10-23 00:55:13 c034b11ec33a httpcore.connection[8] DEBUG close.complete
2024-10-23 00:55:13 c034b11ec33a __main__[8] INFO Found datasets:
[{'@id': 'POST-consumption-prediction',
  '@type': 'dcat:Dataset',
  'dcat:distribution': [{'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpProxy-PUSH'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PULL'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PUSH'}}],
  'id': 'POST-consumption-prediction',
  'name': 'POST /consumption/prediction '
          '(run_consumption_prediction_consumption_prediction_post)',
  'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtUE9TVC1jb25zdW1wdGlvbi1wcmVkaWN0aW9u:UE9TVC1jb25zdW1wdGlvbi1wcmVkaWN0aW9u:NzhkNDJkZGItZGYxOS00MGYxLTgzNDItMGVjZTM1ZWU1MGNi',
                     '@type': 'odrl:Offer',
                     'odrl:obligation': [],
                     'odrl:permission': [],
                     'odrl:prohibition': []}},
 {'@id': 'POST-dummy',
  '@type': 'dcat:Dataset',
  'dcat:distribution': [{'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpProxy-PUSH'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PULL'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PUSH'}}],
  'id': 'POST-dummy',
  'name': 'POST /dummy (process_data_dummy_post)',
  'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtUE9TVC1kdW1teQ==:UE9TVC1kdW1teQ==:ZTJiMTI1YzgtZGQ0Mi00YjlhLTlmMTUtYzNiMzRjNjk0YzNm',
                     '@type': 'odrl:Offer',
                     'odrl:obligation': [],
                     'odrl:permission': [],
                     'odrl:prohibition': []}},
 {'@id': 'GET-consumption',
  '@type': 'dcat:Dataset',
  'dcat:distribution': [{'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpProxy-PUSH'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PULL'}},
                        {'@type': 'dcat:Distribution',
                         'dcat:accessService': 'c6c5a207-1ca3-4aec-9c6e-234990c53169',
                         'dct:format': {'@id': 'HttpData-PUSH'}}],
  'id': 'GET-consumption',
  'name': 'GET /consumption (get_consumption_data_consumption_get)',
  'odrl:hasPolicy': {'@id': 'Y29udHJhY3RkZWYtR0VULWNvbnN1bXB0aW9u:R0VULWNvbnN1bXB0aW9u:OWIyNjA1YzctZTAzMi00NWE5LThhMDYtNzcwMWMxNDNjMTBk',
                     '@type': 'odrl:Offer',
                     'odrl:obligation': [],
                     'odrl:permission': [],
                     'odrl:prohibition': []}}]
```
</details>

## Notes

- The credentials-manager webui is under-developement
- you can use the swagger-ui hosted on **https://{{your_did_web_domain}}/api/v1/docs**


| **Tag**               | **Type** | **URI**                                                 | **Description**                                 |
|-----------------------|----------|---------------------------------------------------------|-------------------------------------------------|
| **Auth**              | POST     | `/login`                                                | Login                                           |
| **DIDs**              | GET      | `/dids`                                                 | Get DIDs                                        |
|                       | POST     | `/dids/create/web`                                      | Create DID                                      |
|                       | DELETE   | `/dids/{did}`                                           | Delete DID                                      |
| **Credentials**       | GET      | `/credentials`                                          | Get Credentials                                 |
|                       | GET      | `/credentials/{credentialId}`                           | View Credential                                 |
|                       | DELETE   | `/credentials/{credentialId}`                           | Delete Credential                               |
| **Credential Exchange**| POST     | `/credentials/useOfferRequest`                          | Accept Credential Offer                         |
|                       | POST     | `/credentials/matchCredentialsForPresentationDefinition`| Match Credentials for Presentation Definition   |
| **DataCellar**        | POST     | `/vc/TermsAndConditions`                                | Get Terms and Conditions                        |
|                       | POST     | `/vc/LegalRegistrationNumber`                           | Get Legal Registration Number                   |
|                       | POST     | `/vc/LegalParticipant`                                  | Get Legal Participant                           |
|                       | POST     | `/vp/self_sign`                                         | VP Self Sign                                    |
|                       | POST     | `/vp/issuer_sign`                                       | VP Issuer Sign                                  |
| **Verifier**          | POST     | `/verify/proof`                                         | Verify Credential Signature                     |

### Register a Legal Participant in the Global Catalogue
To register a legal participant in the global catalogue, run the following task:

```console
$ task credentials-manager:register-legalparticipant-catalogue
```

You will be prompted to enter the ID of the Legal Participant's VP, which was generated in step 4 of the participant deployment process (URL).

> **Note**: The catalogue registration request is sent to the Datacellar IDP, which handles the registration in the catalogue. This process was designed this way for legal and authorization reasons. The Datacellar administrator must approve the registration of a new participant in the catalogue.
> This feature has been implemented but is not fully connected to the global catalogue, as it is not currently deployed.     

<details>
<summary> show logs</summary>

```console
debian@vps-79d2c53f:~/datacellar/dc-participant/deploy/participants/consumer$ task credentials-manager:register-legalparticipant-catalogue
task: [credentials-manager:start-api] docker compose -p consumer up credentials-api --wait
[+] Running 1/1
 ✔ Container consumer.credentials-api  Healthy                                                                                                                                   0.0s 
VP Legal Participant (url or id): https://consumer.datacellar.cosypoc.ovh/vp/bc6ca012-e5bd-46a2-99a0-76edfef0c105.json
2024-10-23 15:01:18.957 | INFO     | __main__:<module>:83 - [Participant DID] -> did:web:consumer.datacellar.cosypoc.ovh:wallet-api:registry:7051ea41-28e2-4fdb-bbf7-ad2c65aa29d9
2024-10-23 15:01:18.957 | INFO     | __main__:<module>:85 - [Global Catalogue] -> register legal participant
2024-10-23 15:01:18.957 | INFO     | __main__:<module>:86 - [LEGAL_PARTICIPANT_ID] -> https://consumer.datacellar.cosypoc.ovh/vp/bc6ca012-e5bd-46a2-99a0-76edfef0c105.json
2024-10-23 15:01:22.268 | INFO     | __main__:<module>:91 - {'status': 'success', 'message': 'All credentials verified successfully', 'details': 'registration legalParticipant into the catalogue is under-construction'}
debian@vps-79d2c53f:~/datacellar/dc-participant/deploy/participants/consumer$ 
```
</details>

## License
This project is licensed under the terms outlined in the [LICENSE](LICENSE) file.
