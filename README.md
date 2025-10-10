

<!--doc_begin-->
### Inputs
|Input|Description|Default|Required|
|-----|-----------|-------|:------:|
|`SECRET_NAMES`|<p>If set, the action will assume that each secret is ONE Value, that needs to be assigned to this environment variable. <br />Used for secrets that contain only the value, in order to assign env var X to value. It does not alter the rest of the behavior.<br />Only works for secrets determined as plain type.</p>|n/a|no|
|`AWS_SECRET_IDS`|AWS secret ids, comma separated if required. Not arn, just the path|n/a|no|
|`AWS_ACCESS_KEY_ID`|AWS Access key id|n/a|no|
|`AWS_SECRET_ACCESS_KEY`|AWS secret access key|n/a|no|
|`AWS_REGION`|AWS region|`us-east-1`|no|
|`SECRETS_2_YAML_FILE`|save secret to this yaml file. If comma separated, each file will be used for the equivalent comma separated secret|``|no|
|`SECRETS_2_JSON_FILE`|save secret to this json file. If comma separated, each file will be used for the equivalent comma separated secret|``|no|
|`SECRETS_2_PLAIN_FILE`|save secret to this plain file (no convertion). If comma separated, each file will be used for the equivalent comma separated secret|``|no|
|`SECRETS_2_ENV_FILE`|save secret to this environment file (key=value). If comma separated, each file will be used for the equivalent comma separated secret|``|no|
|`SECRETS_2_GITHUB_ENV`|add secrets to github env|`False`|no|
|`SECRETS_2_RUNNER_ENV`|add secrets to current env|`False`|no|
|`LOG_LEVEL`|set the log level (INFO|WARNING|DEBUG)|`INFO`|no|
|`APPEND_TO_FILES`|if set, it appends the secret to the specified file(s). Ignored for github env|`False`|no|
|`ADD_QUOTES_TO_ENVVAR_VALUES`|if set, forcibly quotes the values when output and env file|`False`|no|
|`QUOTES_TO_ADD`|if adding quotes, signle or double?|`double`|no|
|`SECRETS_2_YAML_HEADER`|if set, the output yaml is moved under this key. Multiple levels are not supported, single key only|``|no|
|`ACTION_ARGUMENTS`|provide additional command line arguments|``|no|
### Outputs
None
<!--doc_end-->