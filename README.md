[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-pulsedive.svg?branch=develop)](https://api.travis-ci.com/CiscoSecurity/tr-05-serverless-pulsedive)

# Pulsedive Relay API

The API is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Testing

```bash
pip install -U -r test-requirements.txt
```

- Check for *PEP 8* compliance: `flake8 .`.
- Run the suite of unit tests: `pytest -v tests/unit/`.

## Deployment

```bash
pip install -U -r deploy-requirements.txt
```

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Usage

```bash
pip install -U -r use-requirements.txt
```

```bash
export URL=<...>
export JWT=<...>
http POST "${URL}"/health Authorization:"Bearer ${JWT}"
http POST "${URL}"/observe/observables Authorization:"Bearer ${JWT}" < observables.json
```
## API Key

You don't technically need an API key to access the Pulsedive API, but it helps them keep
track of how many requests are being used. If the API key is not used with API
requests, they may use other methods of tracking requests. But, this could be inaccurate 
and the rate limit is set for free users to 30 requests per minute.
They offer additional [pricing plans](https://pulsedive.com/about/?q=api) for increased rate limits. 

## JWT Generating

Payload for encryption must have structure:
```json
{
"key": "your_key_for_pulsedive_api"
}
```

After encryption set your `SECRET_KEY` environment 
variable in AWS lambda for successful decryption in Relay API.
