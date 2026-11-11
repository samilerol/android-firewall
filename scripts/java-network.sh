#!/usr/bin/env bash
# Source this from Bash. Proxy URLs must not contain credentials.
if [[ -f /etc/ssl/certs/java/cacerts ]]; then
  export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts"
fi
if [[ -n "${HTTPS_PROXY:-}" ]]; then
  suite_proxy_properties=$(python3 - <<'PY'
import os,urllib.parse
p=urllib.parse.urlparse(os.environ['HTTPS_PROXY'])
if p.username or p.password:
    raise SystemExit('Credential-bearing proxy URLs are unsupported; use platform authentication')
if p.hostname:
    print(f'-Dhttps.proxyHost={p.hostname} -Dhttps.proxyPort={p.port or 80} -Dhttp.proxyHost={p.hostname} -Dhttp.proxyPort={p.port or 80} -Dhttp.nonProxyHosts=localhost|127.*|[::1]')
PY
)
  export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} $suite_proxy_properties"
  unset suite_proxy_properties
fi
