# Attack profiles

Hotpot profiles are intentionally technology-specific and conservative. They should catch recognizable scanner/exploitation paths without hijacking broad application routes such as every `/api/*`, `/admin`, or `/version` request.

## Core profiles

The original low-risk baseline remains:

- `wordpress` — WordPress discovery, vulnerable-plugin lures, REST/XML-RPC, and canary follow-up
- `secrets` — environment/configuration and credential-file discovery
- `git` — Git/SVN metadata discovery
- `php` — phpMyAdmin, PHPUnit RCE, and common webshell names
- `generic` — generic admin/status and backup-file discovery

## Expanded profiles

### `spring`

Covers Spring Boot Actuator, Jolokia, diagnostic endpoints, and Spring Cloud Gateway route manipulation. Sensitive Actuator and write-style Gateway probes use bounded tarpits.

Representative paths:

- `/actuator/env`
- `/actuator/configprops`
- `/actuator/mappings`
- `/actuator/heapdump`
- `/jolokia/`
- `/actuator/gateway/routes/...`

### `containers`

Covers Docker Engine API discovery/actions and Kubernetes API/credential/exec probes.

Representative paths:

- `/_ping`
- `/v1.45/containers/json`
- `/v1.45/containers/<id>/exec`
- `/api/v1/namespaces`
- `/api/v1/namespaces/<ns>/secrets`
- `/api/v1/namespaces/<ns>/pods/<pod>/exec`
- `/.kube/config`

### `devops`

Covers Jenkins consoles/credentials, CI configuration discovery, package-registry credentials, and Terraform state.

Representative paths:

- `/script`
- `/jenkins/api/json`
- `/credentials/`
- `/.gitlab-ci.yml`
- `/.github/workflows/...`
- `/.npmrc`
- `/.pypirc`
- `/terraform.tfstate`

### `observability`

Covers Grafana, Elasticsearch, Prometheus, Kibana, and Jaeger discovery/data probes.

Representative paths:

- `/grafana/`
- `/_cluster/health`
- `/<index>/_search`
- `/api/v1/status/config`
- `/api/status`
- `/api/services`

### `cms`

Adds non-WordPress CMS coverage for Joomla, Drupal, and Magento.

Representative paths:

- `/administrator/`
- `/index.php?option=com_*`
- `/core/install.php`
- `/user/login`
- `/sites/default/settings.php`
- `/rest/V1/store/storeConfigs`
- `/app/etc/env.php`

### `appliances`

Covers common internet-facing management/VPN discovery for Fortinet, Ivanti/Pulse, Citrix/NetScaler, F5 BIG-IP, SonicWall, and Palo Alto GlobalProtect. Command-style management endpoints are classified as high-severity RCE probes.

Representative paths:

- `/remote/login`
- `/dana-na/`
- `/vpn/index.html`
- `/tmui/login.jsp`
- `/mgmt/tm/util/bash`
- `/sonicui/`
- `/global-protect/login.esp`

## Enabling profiles

Profiles are selected with `HOTPOT_PROFILES`.

The QNAP example enables the expanded set:

```text
HOTPOT_PROFILES=wordpress,spring,containers,devops,observability,cms,appliances,secrets,git,php,generic
```

For other deployments, enable only profiles whose probe paths are not legitimate application endpoints. The technology-specific profiles are not used as allowlists and never cause Hotpot to execute attacker-supplied commands or payloads.

## Response design

Profiles use only static, fake metadata and bounded deception responses. They do not run real vulnerable applications, execute uploaded content, expose real secrets, or emulate command execution. High-signal write/RCE probes may be tarpitted using Hotpot's existing concurrency and lifetime limits.
