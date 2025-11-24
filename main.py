#!/usr/bin/env python3
import os
import boto3    # AWS SDK
import json
import yaml
import base64
from botocore.exceptions import ClientError
import logging
import sys
import re

# ===============================
# Initialize logger
# ===============================

loglevel = getattr(logging, os.environ.get('INPUT_LOG_LEVEL','INFO'))

logger = logging.getLogger(__name__)
logger.setLevel(loglevel)  # Set logger level

# Create handler that logs to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(loglevel)

# Set log format
formatter = logging.Formatter(
	fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
	datefmt="%Y-%m-%d %H:%M:%S"
)
handler.setFormatter(formatter)

# Add handler to logger if not already present
if not logger.handlers:
	logger.addHandler(handler)

# ===============================
# Helper functions
# ===============================

# Convert environment variable input to list
def input_to_array(envvar):
	try:
		result = os.environ[envvar]
		if result:
			if isinstance(result, list):
				result_list = result
			else:
				result_list = result.split(",")
			logger.debug(f"Returning value for {envvar}: ${result}")
			return result_list
		return([])
	except Exception as err:
		logger.debug(f"Env var {envvar} was not found")

# Convert string to boolean
def str_to_bool(s: str) -> bool:
	if isinstance(s, bool):
		return s
	s = s.strip().lower()
	if s in {"true", "t", "yes", "y", "1"}:
		return True
	elif s in {"false", "f", "no", "n", "0"}:
		return False
	else:
		raise ValueError(f"Cannot convert string to bool: {s!r}")

# ===============================
# Initialize environment variables
# ===============================

GITHUB_ENV = os.environ['GITHUB_ENV']
GITHUB_WORKSPACE = os.environ["GITHUB_WORKSPACE"]

APPEND_TO_FILES = os.environ['INPUT_APPEND_TO_FILES']
ADD_QUOTES_TO_ENVVAR_VALUES = os.environ['INPUT_ADD_QUOTES_TO_ENVVAR_VALUES']
QUOTES_TO_ADD = os.environ['INPUT_QUOTES_TO_ADD']
SECRETS_2_YAML_HEADER = os.environ['INPUT_SECRETS_2_YAML_HEADER']
MASK_VALUES = str_to_bool(os.environ['INPUT_MASK_VALUES'])

SECRET_NAMES = input_to_array("INPUT_SECRET_NAMES")
AWS_SECRET_IDS = input_to_array("INPUT_AWS_SECRET_IDS")

SECRETS_2_YAML_FILE = input_to_array('INPUT_SECRETS_2_YAML_FILE')
SECRETS_2_JSON_FILE = input_to_array('INPUT_SECRETS_2_JSON_FILE')
SECRETS_2_PLAIN_FILE = input_to_array('INPUT_SECRETS_2_PLAIN_FILE')
SECRETS_2_ENV_FILE = input_to_array('INPUT_SECRETS_2_ENV_FILE')
SECRETS_2_GITHUB_ENV = str_to_bool(os.environ['INPUT_SECRETS_2_GITHUB_ENV'])
SECRETS_2_RUNNER_ENV = str_to_bool(os.environ['INPUT_SECRETS_2_RUNNER_ENV'])

# Determine file mode based on append setting
if str_to_bool(APPEND_TO_FILES):
	logger.debug("Setting file mode to append")
	file_mode = 'a'
else:
	logger.debug("Setting file mode to overwrite")
	file_mode = 'w'

# ===============================
# Secret type checks
# ===============================

# Check if string is JSON
def is_json(secret):
	try:
		json.loads(secret)
	except Exception as err:
		return False
	return True

# Check if string is YAML
def is_yaml(secret):
	try:
		if (":" in secret) and ("\n" in secret):
			parsed = yaml.safe_load(secret)
			if type(parsed) is dict:
				return True
			else:
				return False		
		else:
			return False
	except Exception as err:
		return False
	return True

# ===============================
# Dictionary and environment helpers
# ===============================

#add github mask
def mask(value):
	if MASK_VALUES:
		print(f"::add-mask::{value}")

# Flatten nested dictionary
def flatten_dict(data, parent_key='', sep='.'):
	items = {}
	for k, v in data.items():
		new_key = f"{parent_key}{sep}{k}" if len(parent_key)>0 else k
		if isinstance(v, dict):
			items.update(flatten_dict(v, new_key, sep=sep))
		else:
			items[new_key] = f"{v}"
	return items

# Add quotes to string if needed
def quote_if_needed(s,force=False):
	s = s.strip()
	if str_to_bool(ADD_QUOTES_TO_ENVVAR_VALUES) or force:
		if not (s.startswith('"') and s.endswith('"')) and not (s.startswith("'") and s.endswith("'")):
			if QUOTES_TO_ADD == 'single':
				return f"'{s.replace('\'', '\\\'')}'"
			else:
				return f'"{s.replace('"', '\\"')}"'
	return s

# Remove surrounding quotes from string
def strip_quotes(s: str) -> str:
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s

# Convert dictionary to environment file format
def dict_to_env(data):
	flattened = flatten_dict(data)
	result = ""
	for key, value in flattened.items():
		result+=f"{key.strip()}={quote_if_needed(value.strip())}\n"
	return result

# ===============================
# Secret parsing helpers
# ===============================

# Convert plain text secret to dictionary
def create_dict_from_plain(content):
	secret_dict = {}
	for line in content.splitlines():
		line = (line.strip()).split('=')
		secret_dict[line[0].strip()] = strip_quotes(line[1].strip())
	return secret_dict

# Convert YAML content to dictionary
def create_dict_from_yaml(content):
	try:
		parsed = yaml.safe_load(content)
		if type(parsed) is dict:
			return parsed
		else:
			raise "Conversion from YAML to dict did not return dictionary"
	except Exception as err:
		logger.error("Converting to dict from YAML failed")
		raise err

# Convert JSON content to environment file
def create_env_from_json(content):
	try:
		return dict_to_env(json.loads(content))
	except Exception as err:
		logger.error("Converting to env from JSON failed")
		raise err

# Convert YAML content to environment file
def create_env_from_yaml(content):
	try:
		return dict_to_env(create_dict_from_yaml(content))
	except Exception as err:
		logger.error("Converting to env from YAML failed")
		raise err

# ===============================
# File write helper
# ===============================

# Write content to file
def write_file(secret_id,content,output_file):
	try:
		logger.debug(f"Writing {secret_id} to file {output_file}" )
		with open(os.path.join(GITHUB_WORKSPACE, output_file), file_mode) as f:
			f.write(content)	
	except Exception as err:
		logger.error(f"Error writing secret {secret_id} to file {output_file}")
		raise err

# ===============================
# Secret conversion helpers
# ===============================

# Convert secret to JSON format
def convert_secret_to_json(secret,filetype):
	dest_type = 'json'
	match filetype:
		case 'json':
			logger.info(f"Converting {filetype} to {dest_type}, no change" )
			result = secret
		case 'yaml':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = json.dumps(create_dict_from_yaml(secret), indent=2)
		case 'plain':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = json.dumps(create_dict_from_plain(secret), indent=2)
		case _:
			logger.error(f"Unknown filetype {filetype}")
			raise f"Unknown filetype {filetype}"	
	logger.debug(f"Converted secret {filetype} value:\n{secret}To {dest_type}:\n{result}")
	return result

# Convert secret to YAML format
def convert_secret_to_yaml(secret,filetype):
	dest_type = 'yaml'
	match filetype:
		case 'json':
			logger.info(f"Converting {filetype} to {dest_type}" )
			if SECRETS_2_YAML_HEADER != '':
				result = yaml.dump( { SECRETS_2_YAML_HEADER: json.loads(secret) }, indent=2, default_style='"')
			else:
				result = yaml.dump(json.loads(secret), indent=2, default_style='"')
		case 'yaml':
			logger.info(f"Converting {filetype} to {dest_type}, no change" )
			result = secret
		case 'plain':
			logger.info(f"Converting {filetype} to {dest_type}" )
			if SECRETS_2_YAML_HEADER != '':
				result = yaml.dump( { SECRETS_2_YAML_HEADER: create_dict_from_plain(secret) }, indent=2)
			else:
				result = yaml.dump(create_dict_from_plain(secret), indent=2)
		case _:
			logger.error(f"Unknown filetype {filetype}")
			raise f"Unknown filetype {filetype}"	
	logger.debug(f"Converted secret {filetype} value:\n{secret}To {dest_type}:\n{result}")
	return result

# Convert secret to environment file format
def convert_secret_to_envfile(secret,filetype):
	dest_type = 'envfile'
	match filetype:
		case 'json':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = create_env_from_json(secret)
		case 'yaml':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = create_env_from_yaml(secret)
		case 'plain':
			logger.info(f"Converting {filetype} to {dest_type}, no change" )
			result = secret
		case _:
			logger.error(f"Unknown filetype {filetype}")
			raise f"Unknown filetype {filetype}"	
	logger.debug(f"Converted secret {filetype} value:\n{secret}To {dest_type}:\n{result}")
	return result

# Convert secret to environment variables (dict)
def convert_secret_to_envvars(secret,filetype):
	dest_type = 'envvars'
	match filetype:
		case 'json':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = flatten_dict(json.loads(secret))
		case 'yaml':
			logger.info(f"Converting {filetype} to {dest_type}" )
			result = flatten_dict(create_dict_from_yaml(secret))
		case 'plain':
			logger.info(f"Converting {filetype} to {dest_type}, no change" )
			result = create_dict_from_plain(secret)
		case _:
			logger.error(f"Unknown filetype {filetype}")
			raise f"Unknown filetype {filetype}"	
	logger.debug(f"Converted secret {filetype} value:\n{secret}To {dest_type}:\n{json.dumps(result,indent = 2)}")
	return result

# ===============================
# Export secrets
# ===============================

def export_secret(secret_id, secret, filetype, idx):
	# Prepend secret name for plain type
	if (len(SECRET_NAMES)>0) and (filetype=="plain"):
		secret = f"{SECRET_NAMES[idx]}={secret}"

	# Export to plain file
	if len(SECRETS_2_PLAIN_FILE)>0: 
		output_file = SECRETS_2_PLAIN_FILE[idx]
		logger.info(f"Exporting {secret_id} as is to plain file {output_file}" )
		write_file(secret_id,secret,output_file)

	# Export to JSON file
	if len(SECRETS_2_JSON_FILE)>0:
		output_file = SECRETS_2_JSON_FILE[idx]
		logger.info(f"Exporting {secret_id} to json file {output_file}" )
		write_file(secret_id,convert_secret_to_json(secret,filetype),output_file)

	# Export to YAML file
	if len(SECRETS_2_YAML_FILE)>0:
		output_file = SECRETS_2_YAML_FILE[idx]
		logger.info(f"Exporting {secret_id} to yaml file {output_file}" )
		write_file(secret_id,convert_secret_to_yaml(secret,filetype),output_file)

	# Export to env file
	if len(SECRETS_2_ENV_FILE)>0:
		output_file = SECRETS_2_ENV_FILE[idx]
		logger.info(f"Exporting {secret_id} to env file {output_file}" )
		write_file(secret_id,convert_secret_to_envfile(secret,filetype),output_file)

	# Export to GitHub environment
	if SECRETS_2_GITHUB_ENV:
		logger.info(f"Exporting {secret_id} to github env" )
		with open(GITHUB_ENV, 'a') as f:
			#f.write(convert_secret_to_envfile(secret,filetype)+"\n")
			for envKey,envValue in convert_secret_to_envvars(secret,filetype).items():
				mask(envValue)
				f.write(f"{envKey}={envValue}\n")


	# Export to runner environment
	if SECRETS_2_RUNNER_ENV:
		logger.info(f"Exporting {secret_id} to runner env" )
		for envKey,envValue in convert_secret_to_envvars(secret,filetype).items():
			mask(envValue)
			os.environ[envKey] = envValue

# ===============================
# AWS environment setup
# ===============================

def prepare_aws_env_var(env_var_name,hide=False):
	logger.debug("Preparing AWS environment")
	try:
		value = os.environ[f"INPUT_{env_var_name}"]
		logger.debug(f"Got {env_var_name} : {"****MASKED****" if hide else value} from INPUT_{env_var_name}, setting it as {env_var_name}")
		os.environ[env_var_name] = value
	except Exception as err:
		logger.warning(f"{env_var_name} not found at env var INPUT_{env_var_name}")

def prepare_aws_env():
	prepare_aws_env_var("AWS_ACCESS_KEY_ID")
	prepare_aws_env_var("AWS_SECRET_ACCESS_KEY",hide=True)
	prepare_aws_env_var("AWS_REGION")

# ===============================
# AWS secret fetch
# ===============================

def get_aws_secret(secret_id):
	logger.info(f"Reading secret {secret_id}")

	try:
		prepare_aws_env()
		session = boto3.session.Session()

		client = session.client(
			service_name='secretsmanager',
			region_name=os.environ["AWS_REGION"],
		)

		response = client.get_secret_value(
			SecretId=secret_id
		)	
		logger.debug(f"Got Response:\n{response}")

		# Decode secret
		if 'SecretString' in response:
			ksecret = response['SecretString']
		else:
			ksecret = base64.b64decode(response['SecretBinary'])

		logger.debug(f"Got secret:\n{ksecret}")

		# Determine secret type
		if is_json(ksecret):
			logger.info("Secret is in json format")
			return ksecret, 'json'
		elif is_yaml(ksecret):
			logger.info("Secret is in yaml format")
			return ksecret, 'yaml'
		else:
			logger.info("Secret is assumed to be plain text")
			return ksecret, 'plain'

	except Exception as err:
		logger.error(f"Error reading secret {secret_id}:{err}")
		raise err

# ===============================
# Main execution
# ===============================

def main():
	# Test mode
	if len(sys.argv) > 1 : 
		if sys.argv[1] == "--test":
			test()
			return

	# Fetch and export secrets
	if len(AWS_SECRET_IDS)>0:
		logger.debug(f"Reading secrets from AWS {AWS_SECRET_IDS}")
		for idx, secret_id in enumerate(AWS_SECRET_IDS):
			secret, filetype = get_aws_secret(secret_id)
			export_secret(secret_id, secret, filetype, idx)
	else:
		logger.info("No secrets were provided, doing nothing!")

# ===============================
# Test function
# ===============================

def test():
	logger.info(f"Starting tests")

	global SECRET_NAMES
	global SECRETS_2_YAML_FILE
	global SECRETS_2_ENV_FILE
	global SECRETS_2_JSON_FILE
	global SECRETS_2_PLAIN_FILE

	# Create results directory
	if not os.path.exists(".results"):
		os.mkdir(".results") 
	
	for filetype in ['json','yaml','plain','single']:
		logger.info(f"Testing {filetype} input")

		SECRET_NAMES = ["FETCHER_single_key1"]
		SECRETS_2_YAML_FILE = [f".results/test_{filetype}2yaml"]
		SECRETS_2_ENV_FILE = [f".results/test_{filetype}2env"]
		SECRETS_2_JSON_FILE = [f".results/test_{filetype}2json"]
		SECRETS_2_PLAIN_FILE = [f".results/test_{filetype}2plain"]

		with open(f'tests/test.{filetype}', 'r') as secret_file:
			secret = secret_file.read()
		logger.info(f"Working on file test_{filetype} with content:\n{secret}\n")
		export_secret(f"test_{filetype}", secret, filetype.replace('single','plain'), 0)

		# Show results
		logger.info("Showing results:")
		for file in [SECRETS_2_YAML_FILE[0],SECRETS_2_ENV_FILE[0],SECRETS_2_JSON_FILE[0],SECRETS_2_PLAIN_FILE[0]]:
			logger.info(f"\nFile: {file}\n")
			if os.path.isfile(file):
				with open(file, 'r') as f:
					logger.info(f.read())

		if SECRETS_2_RUNNER_ENV:
			logger.info(f"\nEnv vars:\n")
			pattern = re.compile(r"^FETCHER")
			fetcher_env = {k: v for k, v in os.environ.items() if pattern.match(k)}
			for key, value in fetcher_env.items():
			    logger.info(f"{key}={value}")			

# ===============================
# Script entry point
# ===============================

if __name__ == "__main__":
	main()
