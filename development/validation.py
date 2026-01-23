import tomllib
import argparse
import sys
import os

def load_alert_config(file_path):
    """
    Loads the TOML configuration from the specified file path.
    Handles FileNotFoundError if the file doesn't exist.
    """
    try:
        with open(file_path, "rb") as toml_file:
            return tomllib.load(toml_file)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)
    except tomllib.TOMLDecodeError as e:
        print(f"Error: Could not decode TOML file '{file_path}': {e}")
        sys.exit(1)

def get_required_fields(rule_type):
    """
    Returns a list of required fields based on the alert rule type.
    """
    base_fields = ['description', 'name', 'risk_score', 'severity', 'type']

    if rule_type == "query":
        return base_fields + ['query']
    elif rule_type == "eql":
        return base_fields + ['query', 'language']
    elif rule_type == "threshold":
        return base_fields + ['query', 'threshold']
    else:
        print(f"Warning: Unknown rule type '{rule_type}'. No specific fields enforced beyond base.")
        return base_fields

def validate_alert_config(alert_config, file_path):
    # sourcery skip: use-named-expression
    """
    Validates the alert configuration against required fields.
    """
    if 'rule' not in alert_config or 'type' not in alert_config['rule']:
        print(f"Error: 'rule' or 'rule.type' not found in '{file_path}'. Cannot validate.")
        sys.exit(1)

    rule_type = alert_config['rule']['type']
    required_fields = get_required_fields(rule_type)

    # Collect all present fields from the top-level tables
    present_fields = set()
    for table_name in alert_config:
        present_fields.update(alert_config[table_name].keys())

    missing_fields = [field for field in required_fields if field not in present_fields]

    if missing_fields:
        print(f"The following fields do not exist in {file_path}: {missing_fields}")
    else:
        print(f"Validation Passed for: {file_path}")

def main():
    """
    Main function to orchestrate the script execution.
    """
    parser = argparse.ArgumentParser(
        description="Validate a TOML alert configuration file."
    )
    # Define the --file argument as the primary way to specify the TOML file.
    # Set a default value and allow environment variable override.
    parser.add_argument(
        '-f', '--file',
        type=str,
        default=os.environ.get("ALERT_TOML_FILE", "alert_example.toml"),
        help="Path to the TOML alert configuration file. "
            "Defaults to ALERT_TOML_FILE environment variable or 'alert_example.toml'."
    )
    # The -p/--path argument seems redundant if -f/--file specifies the file.
    # If it was intended for a directory where the file resides, it needs different logic.
    # For now, let's remove it or clarify its purpose. Assuming it's redundant.
    # parser.add_argument('-p', '--path', help='(Optional) Path to a directory containing the TOML file.')

    args = parser.parse_args()

    file_path = args.file # Use the path from argparse

    alert_config = load_alert_config(file_path)
    validate_alert_config(alert_config, file_path)

if __name__ == "__main__":
    main()