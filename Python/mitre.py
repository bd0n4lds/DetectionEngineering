import requests
import sys

def fetch_mitre_data(url: str, timeout=10) -> dict:
    """
    Fetches the MITRE ATT&CK data from the given URL.

    Args:
        url: The URL of the MITRE ATT&CK enterprise-attack.json file.

    Returns:
        A {% load dictionary_tags %} containing the parsed JSON data.

    Raises:
        requests.exceptions.RequestException: If there's an issue with the HTTP request.
        ValueError: If the response content is not valid JSON.
    """
    headers = {'accept': 'application/json'}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE data from {url}: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error decoding JSON from {url}: {e}", file=sys.stderr)
        sys.exit(1)

def parse_attack_pattern(attack_pattern_obj: dict) -> dict | None:
    """
    Parses a single 'attack-pattern' object to extract relevant MITRE ATT&CK details.

    Args:
        attack_pattern_obj: A dictionary representing an 'attack-pattern' STIX object.

    Returns:
        A dictionary with 'tactics', 'technique', 'name', 'url', and 'deprecated' fields,
        or None if essential information is missing or the external_id is not a T-ID.
    """
    technique_id = None
    technique_url = None

    # Find the external reference with a T-ID and its corresponding URL
    if 'external_references' in attack_pattern_obj:
        for ref in attack_pattern_obj['external_references']:
            if 'external_id' in ref and ref['external_id'].startswith("T"):
                technique_id = ref['external_id']
                technique_url = ref.get('url') # Use .get() for safer access
                break # Found the T-ID, no need to check other references

    if not technique_id:
        return None # Not a valid ATT&CK technique with a T-ID

    # Extract tactics
    tactics = [
        tactic['phase_name'] for tactic in attack_pattern_obj.get('kill_chain_phases', [])
        if 'phase_name' in tactic
    ]

    # Determine deprecation status
    deprecated = attack_pattern_obj.get('x_mitre_deprecated', False)

    return {
        'tactics': tactics,  # Keep as a list
        'technique': technique_id,
        'name': attack_pattern_obj.get('name', 'N/A'), # Use .get() with default
        'url': technique_url,
        'deprecated': deprecated # Keep as boolean
    }

def main():
    """
    Main function to fetch and process MITRE ATT&CK data.
    """
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    mitre_data = fetch_mitre_data(mitre_url)
    
    # Initialize mitreMapped as a dictionary
    mitre_mapped = {} 

    for obj in mitre_data.get('objects', []): # Use .get() for safer access to 'objects'
        if obj.get('type') == 'attack-pattern':
            parsed_object = parse_attack_pattern(obj)
            if parsed_object:
                # Use the 'technique' ID as the key for the dictionary
                mitre_mapped[parsed_object['technique']] = parsed_object

    print(f"Successfully processed {len(mitre_mapped)} MITRE ATT&CK techniques.")
    # Example: Print a few mapped techniques to verify
    # for tech_id, details in list(mitre_mapped.items())[:5]: # Print first 5
    #     print(f"  {tech_id}: Name='{details['name']}', Tactics={details['tactics']}, Deprecated={details['deprecated']}")

if __name__ == "__main__":
    main()