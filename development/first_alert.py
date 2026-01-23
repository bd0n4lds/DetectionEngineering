import requests
import json

def send_elastic_request(url: str, api_key: str, data_payload: dict) -> dict | None:
    """
    Sends a POST request to an Elasticsearch-like endpoint.

    Args:
        url (str): The URL to send the request to.
        api_key (str): The API key for authorization.
        data_payload (dict): The dictionary containing the JSON data payload.

    Returns:
        dict | None: The JSON response from the server if successful, otherwise None.
    """
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'kbn-xsrf': 'true',
        'Authorization': f'ApiKey {api_key}',
    }

    try:
        # requests.post can take a dictionary directly for the json parameter,
        # which it will automatically serialize to JSON and set the Content-Type header.
        response = requests.post(url, headers=headers, json=data_payload)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Response: {response.text}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected request error occurred: {req_err}")
    except json.JSONDecodeError as json_err:
        print(f"Failed to decode JSON response: {json_err} - Response text: {response.text}")
    return None

# --- Example Usage ---
# Define your URL and API Key
your_url = "/api/detection_engine/rules" # Replace with your actual URL
your_api_key = "ew342234dsdfgsd"

# Define the data payload as a Python dictionary
your_data_payload = {
    "from": "now-70m",
    "name": "MS Office child process",
    "tags": [
        "child process",
        "ms office"
    ],
    "type": "query",
    "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
    "enabled": False,
    "filters": [
        {
            "query": {
                "match": {
                    "event.action": {
                        "type": "phrase",
                        "query": "Process Create (rule: ProcessCreate)"
                    }
                }
            }
        }
    ],
    "rule_id": "process_started_by_ms_office_program",
    "interval": "1h",
    "language": "kuery",
    "severity": "low",
    "risk_score": 50,
    "description": "Process started by MS Office program - possible payload",
    "required_fields": [
        {
            "name": "process.parent.name",
            "type": "keyword"
        }
    ],
    "related_integrations": [
        {
            "package": "o365",
            "version": "^2.3.2"
        }
    ]
}

# Call the function to send the request
elastic_data = send_elastic_request(your_url, your_api_key, your_data_payload)

if elastic_data:
    print("Successfully received data:")
    # print(json.dumps(elastic_data, indent=2)) # Uncomment to print the full JSON response
else:
    print("Failed to retrieve data.")