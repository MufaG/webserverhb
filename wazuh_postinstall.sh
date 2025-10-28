#!/usr/bin/env bash
set -euo pipefail

#############################
#        PARÂMETROS         #
#############################
# --- Identidade/host ---
WAZUH_IP="${WAZUH_IP:-$(hostname -I | awk '{print $1}')}"
WAZUH_HOSTNAME="${WAZUH_HOSTNAME:-wazuh-manager}"

# --- Credenciais painéis/integrações ---
DASHBOARD_ADMIN_PASSWORD="${DASHBOARD_ADMIN_PASSWORD:-ChangeMe_Safe!123}"

# E-mail (SMTP)
ENABLE_EMAIL="${ENABLE_EMAIL:-yes}"               # yes|no
SMTP_SERVER="${SMTP_SERVER:-smtp.seudominio.com}"
SMTP_PORT="${SMTP_PORT:-587}"                      # 25|465|587
SMTP_FROM="${SMTP_FROM:-wazuh@seudominio.com}"
SMTP_TO="${SMTP_TO:-soc@seudominio.com,ti@seudominio.com}"
SMTP_AUTH_USER="${SMTP_AUTH_USER:-}"              # vazio se não usar auth
SMTP_AUTH_PASS="${SMTP_AUTH_PASS:-}"              # vazio se não usar auth
SMTP_TLS="${SMTP_TLS:-yes}"                        # yes|no

# Telegram (alertas)
ENABLE_TELEGRAM="${ENABLE_TELEGRAM:-yes}"         # yes|no
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Webhook n8n (alertas)
ENABLE_N8N="${ENABLE_N8N:-yes}"                   # yes|no
N8N_WEBHOOK_URL="${N8N_WEBHOOK_URL:-}"            # ex: https://n8n.seudominio.com/webhook/XXXXXXXX

# OpenCTI (pull de IOCs -> listas CDB)
ENABLE_OPENCTI="${ENABLE_OPENCTI:-yes}"           # yes|no
OPENCTI_URL="${OPENCTI_URL:-https://opencti.seu.local}"
OPENCTI_TOKEN="${OPENCTI_TOKEN:-}"                # API token
OPENCTI_LABEL_FILTER="${OPENCTI_LABEL_FILTER:-malicious}" # filtrar por label
OPENCTI_LOOKBACK_HOURS="${OPENCTI_LOOKBACK_HOURS:-24}"    # últimos X horas
OPENCTI_PULL_INTERVAL_MIN="${OPENCTI_PULL_INTERVAL_MIN:-30}"

#############################
#    DETEÇÃO DE CAMINHOS    #
#############################
WZ_ETC="/var/ossec/etc"
WZ_BIN="/var/ossec/bin"
WZ_AR_BIN="/var/ossec/active-response/bin"
WZ_INT_DIR="/var/ossec/integrations"
WZ_LISTS_DIR="$WZ_ETC/lists"
WZ_RULES_DIR="$WZ_ETC/rules"
WZ_DEC_DIR="$WZ_ETC/decoders"
WZ_BACKUP_DIR="/opt/wazuh/backups"
DASHBOARD_PWD_TOOL="/usr/share/wazuh-dashboard/utils/wazuh-passwords-tool.sh"

# Serviços (systemd)
SVC_MANAGER="wazuh-manager"
SVC_INDEXER="wazuh-indexer"
SVC_DASHBOARD="wazuh-dashboard"

echo "==> Wazuh pós-instalação | IP: $WAZUH_IP | Hostname: $WAZUH_HOSTNAME"

#############################
#   PRÉ-CHECKS & PREP       #
#############################
echo "==> Atualizar pacotes..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

echo "==> Garantir utilitários..."
apt-get install -y jq curl ufw xmlstarlet python3 python3-venv python3-pip

echo "==> Definir hostname..."
hostnamectl set-hostname "$WAZUH_HOSTNAME" || true

echo "==> Configurar firewall UFW..."
ufw allow 22/tcp || true
ufw allow 443/tcp || true       # Dashboard
ufw allow 1514/tcp || true      # Agents (TCP/UDP)
ufw allow 1514/udp || true
ufw allow 1515/tcp || true      # Enrollment/registration
ufw allow 55000/tcp || true     # API/agent installer service
yes | ufw enable || true
ufw status | sed 's/^/  /'

#############################
#        HARDENING          #
#############################
echo "==> Alterar password do Wazuh Dashboard (utilizador admin)..."
if [[ -x "$DASHBOARD_PWD_TOOL" ]]; then
  "$DASHBOARD_PWD_TOOL" --user admin --password "$DASHBOARD_ADMIN_PASSWORD"
else
  echo "  [AVISO] Não encontrei $DASHBOARD_PWD_TOOL; a password do dashboard não foi alterada."
fi

echo "==> Forçar TLS >= 1.2 no Manager (se aplicável) e ativar opções seguras..."
OSSEC_CONF="$WZ_ETC/ossec.conf"
cp -a "$OSSEC_CONF" "$OSSEC_CONF.bak.$(date +%F_%H%M%S)"

# Garante tags essenciais; cria se não existirem
ensure_xml_node () {
  local xpath="$1" ; local xml="$2" ; local node_xml="$3"
  if ! xmlstarlet sel -t -c "$xpath" "$xml" >/dev/null 2>&1; then
    # insere antes do fechamento de <ossec_config>
    xmlstarlet ed -P -L -s "/ossec_config" -t elem -n TMPNODE -v "" \
      -u "//TMPNODE" -x "$node_xml" \
      -d "//TMPNODE" "$xml"
  fi
}

# Secções <global> email + opções
if [[ "$ENABLE_EMAIL" == "yes" ]]; then
  ensure_xml_node "/ossec_config/global" "$OSSEC_CONF" "<global></global>"
  xmlstarlet ed -P -L \
    -u "/ossec_config/global/email_notification" -v "yes" \
    "$OSSEC_CONF" || xmlstarlet ed -P -L \
      -s "/ossec_config/global" -t elem -n email_notification -v "yes" "$OSSEC_CONF"

  # múltiplos destinatários separados por vírgula
  if xmlstarlet sel -t -v "/ossec_config/global/email_to" "$OSSEC_CONF" >/dev/null 2>&1; then
    xmlstarlet ed -P -L -u "/ossec_config/global/email_to" -v "$SMTP_TO" "$OSSEC_CONF"
  else
    xmlstarlet ed -P -L -s "/ossec_config/global" -t elem -n email_to -v "$SMTP_TO" "$OSSEC_CONF"
  fi

  for pair in "email_from:$SMTP_FROM" "smtp_server:$SMTP_SERVER" "smtp_port:$SMTP_PORT"; do
    k="${pair%%:*}"; v="${pair#*:}"
    if xmlstarlet sel -t -v "/ossec_config/global/$k" "$OSSEC_CONF" >/dev/null 2>&1; then
      xmlstarlet ed -P -L -u "/ossec_config/global/$k" -v "$v" "$OSSEC_CONF"
    else
      xmlstarlet ed -P -L -s "/ossec_config/global" -t elem -n "$k" -v "$v" "$OSSEC_CONF"
    fi
  done

  # TLS/auth opcional
  if [[ -n "$SMTP_AUTH_USER" && -n "$SMTP_AUTH_PASS" ]]; then
    xmlstarlet ed -P -L \
      -s "/ossec_config/global" -t elem -n email_authentication -v "yes" \
      -s "/ossec_config/global" -t elem -n email_user -v "$SMTP_AUTH_USER" \
      -s "/ossec_config/global" -t elem -n email_password -v "$SMTP_AUTH_PASS" \
      "$OSSEC_CONF"
  fi
  if [[ "$SMTP_TLS" == "yes" ]]; then
    if xmlstarlet sel -t -v "/ossec_config/global/email_use_tls" "$OSSEC_CONF" >/dev/null 2>&1; then
      xmlstarlet ed -P -L -u "/ossec_config/global/email_use_tls" -v "yes" "$OSSEC_CONF"
    else
      xmlstarlet ed -P -L -s "/ossec_config/global" -t elem -n email_use_tls -v "yes" "$OSSEC_CONF"
    fi
  fi
fi

# Garante diretórios
mkdir -p "$WZ_BACKUP_DIR" "$WZ_LISTS_DIR" "$WZ_AR_BIN" "$WZ_INT_DIR"

#############################
#     BACKUPS AUTOMÁTICOS   #
#############################
echo "==> Configurar backups diários de configuração..."
cat > /usr/local/sbin/wazuh_backup_config.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STAMP="$(date +%F_%H%M%S)"
DEST="/opt/wazuh/backups/$STAMP"
mkdir -p "$DEST"
tar -C / -czf "$DEST/wazuh_config.tgz" var/ossec/etc var/ossec/active-response/bin var/ossec/integrations || true
echo "$STAMP" > /opt/wazuh/backups/LATEST
find /opt/wazuh/backups -maxdepth 1 -type d -mtime +14 -exec rm -rf {} \; 2>/dev/null || true
EOF
chmod +x /usr/local/sbin/wazuh_backup_config.sh

cat > /etc/cron.d/wazuh_backup <<'EOF'
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
0 3 * * * root /usr/local/sbin/wazuh_backup_config.sh
EOF

#############################
#  ALERTAS: TELEGRAM & n8n  #
#############################
if [[ "$ENABLE_TELEGRAM" == "yes" && -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
  echo "==> Criar Active Response para Telegram..."
  cat > "$WZ_AR_BIN/telegram-alert.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
read -r PAYLOAD
# Consome restantes linhas se existirem (stdin completo)
while read -r line; do PAYLOAD="\$PAYLOAD\n\$line"; done || true
API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
MSG="\$(echo -e "\$PAYLOAD" | jq -r 'if type=="object" then .full_log // .predecoder // tostring else tostring end' 2>/dev/null || echo "\$PAYLOAD")"
curl -sS -X POST "\$API" -d chat_id="${TELEGRAM_CHAT_ID}" -d disable_web_page_preview=true --data-urlencode "text=\$MSG" >/dev/null
exit 0
EOF
  chmod +x "$WZ_AR_BIN/telegram-alert.sh"

  # Regista comando e active-response (nível >=10)
  xmlstarlet ed -P -L \
    -s "/ossec_config" -t elem -n command -v "" \
    -s "/ossec_config/command[last()]" -t elem -n name -v "telegram-alert" \
    -s "/ossec_config/command[last()]" -t elem -n executable -v "telegram-alert.sh" \
    -s "/ossec_config/command[last()]" -t elem -n timeout_allowed -v "no" \
    "$OSSEC_CONF"

  xmlstarlet ed -P -L \
    -s "/ossec_config" -t elem -n active-response -v "" \
    -s "/ossec_config/active-response[last()]" -t elem -n command -v "telegram-alert" \
    -s "/ossec_config/active-response[last()]" -t elem -n location -v "local" \
    -s "/ossec_config/active-response[last()]" -t elem -n level -v "10" \
    "$OSSEC_CONF"
else
  echo "==> Telegram desativado ou sem credenciais — a saltar."
fi

if [[ "$ENABLE_N8N" == "yes" && -n "$N8N_WEBHOOK_URL" ]]; then
  echo "==> Criar Active Response para webhook n8n..."
  cat > "$WZ_AR_BIN/n8n-webhook.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PAYLOAD="\$(cat)"
curl -sS -X POST "$N8N_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  --data "\$PAYLOAD" >/dev/null
exit 0
EOF
  chmod +x "$WZ_AR_BIN/n8n-webhook.sh"

  xmlstarlet ed -P -L \
    -s "/ossec_config" -t elem -n command -v "" \
    -s "/ossec_config/command[last()]" -t elem -n name -v "n8n-webhook" \
    -s "/ossec_config/command[last()]" -t elem -n executable -v "n8n-webhook.sh" \
    -s "/ossec_config/command[last()]" -t elem -n timeout_allowed -v "no" \
    "$OSSEC_CONF"

  xmlstarlet ed -P -L \
    -s "/ossec_config" -t elem -n active-response -v "" \
    -s "/ossec_config/active-response[last()]" -t elem -n command -v "n8n-webhook" \
    -s "/ossec_config/active-response[last()]" -t elem -n location -v "local" \
    -s "/ossec_config/active-response[last()]" -t elem -n level -v "10" \
    "$OSSEC_CONF"
else
  echo "==> n8n desativado ou sem URL — a saltar."
fi

#############################
#  OPENCTI -> LISTAS CDB    #
#############################
if [[ "$ENABLE_OPENCTI" == "yes" ]]; then
  echo "==> Instalar conector simples OpenCTI -> Wazuh CDB lists..."
  APP_DIR="/opt/wazuh-opencti-puller"
  python3 -m venv "$APP_DIR/venv"
  "$APP_DIR/venv/bin/pip" install --upgrade pip requests

  mkdir -p "$APP_DIR"
  cat > "$APP_DIR/opencti_to_cdb.py" <<EOF
#!/usr/bin/env python3
import os, sys, time, json, requests, datetime
OPENCTI_URL = os.getenv("OPENCTI_URL", "$OPENCTI_URL").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN", "$OPENCTI_TOKEN")
LABEL = os.getenv("OPENCTI_LABEL_FILTER", "$OPENCTI_LABEL_FILTER")
LOOKBACK_H = int(os.getenv("OPENCTI_LOOKBACK_HOURS", "$OPENCTI_LOOKBACK_HOURS"))
OUT_DIR = "$WZ_LISTS_DIR"
os.makedirs(OUT_DIR, exist_ok=True)

if not OPENCTI_TOKEN:
    print("Missing OPENCTI_TOKEN", file=sys.stderr); sys.exit(1)

# Query simples (rest API) — buscar observables recentes com label
since = (datetime.datetime.utcnow() - datetime.timedelta(hours=LOOKBACK_H)).strftime("%Y-%m-%dT%H:%M:%SZ")
headers = {"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json", "Accept": "application/json"}

# Coleções
ips, domains, urls, hashes = set(), set(), set(), set()

# Nota: endpoints OpenCTI podem variar conforme versão/ES. Usamos rest/search genérico.
# Ajusta conforme o teu OpenCTI (ex.: /api/v1/observables /api/v1/indicators).
def fetch(path, params):
    r = requests.get(f"{OPENCTI_URL}{path}", headers=headers, params=params, timeout=60)
    r.raise_for_status()
    return r.json()

try:
    # Exemplo com /api/v1/observables (fallback via /api/v1/indicators se necessário)
    # Tentamos ambos de forma simplificada.
    endpoints = [
        ("/api/v1/observables", {"search": LABEL, "filters": json.dumps({"mode":"and","filters":[{"key":"created_at","values":[since],"operator":"gt"}]})}),
        ("/api/v1/indicators", {"search": LABEL, "filters": json.dumps({"mode":"and","filters":[{"key":"created_at","values":[since],"operator":"gt"}]})})
    ]
    for path, params in endpoints:
        try:
            data = fetch(path, params)
        except Exception:
            continue
        items = data if isinstance(data, list) else data.get("data", [])
        for it in items:
            val = it.get("observable_value") or it.get("pattern", "")
            if not val: continue
            v = str(val).strip()
            if v.startswith("[") and v.endswith("]"):  # STIX pattern
                # pull simples de STIX: 'url-value = 'http://...'' etc.
                for token in v.replace("'", '"').split('"'):
                    if token.startswith("http"):
                        urls.add(token)
                    elif token.count(".")>=1 and " " not in token:
                        domains.add(token)
            else:
                if v.count(".")>=3 and all(p.isdigit() or p=="" for p in v.split(".")):
                    ips.add(v)
                elif v.startswith("http"):
                    urls.add(v)
                elif v.count(".")>=1 and " " not in v:
                    domains.add(v)
                elif len(v) in (32,40,64) and all(c in "0123456789abcdefABCDEF" for c in v):
                    hashes.add(v)
except Exception as e:
    print("Error fetching OpenCTI:", e, file=sys.stderr)

def write_cdb(name, values):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w") as f:
        for v in sorted(values):
            f.write(f"{v} : 1\n")
    return path

ipf = write_cdb("ioc_opencti_ips.cdb", ips)
domf = write_cdb("ioc_opencti_domains.cdb", domains)
urlf = write_cdb("ioc_opencti_urls.cdb", urls)
hashf = write_cdb("ioc_opencti_hashes.cdb", hashes)

print(json.dumps({
    "counts":{"ips":len(ips),"domains":len(domains),"urls":len(urls),"hashes":len(hashes)},
    "files":[ipf, domf, urlf, hashf]
}))
EOF
  chmod +x "$APP_DIR/opencti_to_cdb.py"

  # systemd service + timer
  cat > /etc/systemd/system/wazuh-opencti-puller.service <<EOF
[Unit]
Description=Wazuh OpenCTI IOC Puller
After=network-online.target

[Service]
Type=oneshot
Environment=OPENCTI_URL=$OPENCTI_URL
Environment=OPENCTI_TOKEN=$OPENCTI_TOKEN
Environment=OPENCTI_LABEL_FILTER=$OPENCTI_LABEL_FILTER
Environment=OPENCTI_LOOKBACK_HOURS=$OPENCTI_LOOKBACK_HOURS
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/opencti_to_cdb.py
User=root
Group=ossec

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/wazuh-opencti-puller.timer <<EOF
[Unit]
Description=Run Wazuh OpenCTI Puller every ${OPENCTI_PULL_INTERVAL_MIN} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${OPENCTI_PULL_INTERVAL_MIN}min
Unit=wazuh-opencti-puller.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now wazuh-opencti-puller.timer

  echo "==> Declarar listas CDB no ossec.conf..."
  # <ruleset><list>...
  ensure_xml_node "/ossec_config/ruleset" "$OSSEC_CONF" "<ruleset></ruleset>"
  for fname in ioc_opencti_ips.cdb ioc_opencti_domains.cdb ioc_opencti_urls.cdb ioc_opencti_hashes.cdb; do
    if ! grep -q "$fname" "$OSSEC_CONF"; then
      xmlstarlet ed -P -L \
        -s "/ossec_config/ruleset" -t elem -n list -v "" \
        -s "/ossec_config/ruleset/list[last()]" -t attr -n type -v "cdb" \
        -s "/ossec_config/ruleset/list[last()]" -t attr -n load -v "yes" \
        -s "/ossec_config/ruleset/list[last()]" -t elem -n path -v "$WZ_LISTS_DIR/$fname" \
        -s "/ossec_config/ruleset/list[last()]" -t elem -n name -v "${fname%.cdb}" \
        "$OSSEC_CONF"
    fi
  done

  echo "==> Regras e decoders para cruzar eventos com listas OpenCTI..."
  # Decoder simples para URL/IP/Hash em mensagens genéricas (fallback)
  cat > "$WZ_DEC_DIR/opencti-generic-decoder.xml" <<'EOF'
<decoders>
  <decoder name="opencti-generic">
    <prematch>.*</prematch>
    <regex offset="after_prematch">srcip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})</regex>
    <order>srcip</order>
  </decoder>
  <decoder name="opencti-url">
    <prematch>.*</prematch>
    <regex offset="after_prematch">url=([^ ]+)</regex>
    <order>url</order>
  </decoder>
  <decoder name="opencti-hash">
    <prematch>.*</prematch>
    <regex offset="after_prematch">hash=([a-fA-F0-9]{32,64})</regex>
    <order>hash</order>
  </decoder>
</decoders>
EOF

  # Regra: se srcip/url/hash estiver nas listas CDB -> alerta alto
  cat > "$WZ_RULES_DIR/opencti-lookup-rules.xml" <<'EOF'
<group name="opencti,">
  <rule id="100100" level="12">
    <if_matched_sid>0</if_matched_sid>
    <description>IOC match (IP) from OpenCTI CDB list</description>
    <options>no_full_log</options>
    <list field="srcip" lookup="match_key">ioc_opencti_ips</list>
  </rule>
  <rule id="100101" level="12">
    <if_matched_sid>0</if_matched_sid>
    <description>IOC match (Domain/URL) from OpenCTI CDB list</description>
    <options>no_full_log</options>
    <list field="url" lookup="match_key">ioc_opencti_urls</list>
    <list field="hostname" lookup="match_key">ioc_opencti_domains</list>
  </rule>
  <rule id="100102" level="12">
    <if_matched_sid>0</if_matched_sid>
    <description>IOC match (HASH) from OpenCTI CDB list</description>
    <options>no_full_log</options>
    <list field="hash" lookup="match_key">ioc_opencti_hashes</list>
  </rule>
</group>
EOF
else
  echo "==> Integração OpenCTI desativada — a saltar."
fi

#############################
#   SCRIPTS DE AGENTES      #
#############################
echo "==> Gerar scripts de instalação de agentes..."
AGENT_DIR="/opt/wazuh/agents"
mkdir -p "$AGENT_DIR"

# Windows (.ps1)
cat > "$AGENT_DIR/install_agent_windows.ps1" <<EOF
# Executar em PowerShell como Administrador
param(
  [string]\$ManagerIP = "$WAZUH_IP",
  [string]\$AgentName = "\$env:COMPUTERNAME"
)
Write-Host "Descarregar Wazuh Agent MSI do Manager..." -ForegroundColor Cyan
\$msi = "\$env:TEMP\\wazuh-agent.msi"
Invoke-WebRequest -Uri ("https://{0}:55000/agent" -f \$ManagerIP) -OutFile \$msi -UseBasicParsing
Write-Host "Instalar agente..." -ForegroundColor Cyan
Start-Process msiexec.exe -Wait -ArgumentList "/i `"\$msi`" /qn ADDRESS=\$ManagerIP AGENT_NAME=\$AgentName"
Write-Host "Iniciar e ativar serviço..." -ForegroundColor Cyan
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
Write-Host "Concluído." -ForegroundColor Green
EOF

# Linux (.sh)
cat > "$AGENT_DIR/install_agent_linux.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
MANAGER_IP="${WAZUH_IP}"
AGENT_NAME="\${1:-\$(hostname)}"

if command -v apt-get >/dev/null 2>&1; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
  sudo apt-get update -y && sudo apt-get install -y wazuh-agent
elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
  sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat <<REPO | sudo tee /etc/yum.repos.d/wazuh.repo
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
REPO
  (command -v dnf && sudo dnf install -y wazuh-agent) || sudo yum install -y wazuh-agent
else
  echo "Gestor de pacotes não suportado"; exit 1
fi

sudo sed -i "s|<address>.*</address>|<address>\${MANAGER_IP}</address>|" /var/ossec/etc/ossec.conf
sudo sed -i "s|<agent_name>.*</agent_name>|<agent_name>\${AGENT_NAME}</agent_name>|" /var/ossec/etc/ossec.conf || \
  sudo xmlstarlet ed -P -L -s "/ossec_config" -t elem -n agent_name -v "\${AGENT_NAME}" /var/ossec/etc/ossec.conf

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
echo "Agente instalado e iniciado."
EOF
chmod +x "$AGENT_DIR/install_agent_linux.sh"

#############################
#    TESTE DE ALERTA        #
#############################
echo "==> Gerar teste de alerta (simulação de comando inválido)..."
cat > /var/ossec/logs/test_wazuh.log <<'EOF'
Jan 01 00:00:00 host app[1234]: url=http://malicious.test/path srcip=203.0.113.99 hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF

# Adiciona log customizado ao localfile (se não existir)
if ! grep -q "test_wazuh.log" "$OSSEC_CONF"; then
  xmlstarlet ed -P -L \
    -s "/ossec_config" -t elem -n localfile -v "" \
    -s "/ossec_config/localfile[last()]" -t elem -n log_format -v "syslog" \
    -s "/ossec_config/localfile[last()]" -t elem -n location -v "/var/ossec/logs/test_wazuh.log" \
    "$OSSEC_CONF"
fi

#############################
#     RESTART & STATUS      #
#############################
echo "==> Reiniciar serviços Wazuh..."
systemctl restart "$SVC_MANAGER" || true
systemctl restart "$SVC_DASHBOARD" || true
systemctl restart "$SVC_INDEXER" || true

sleep 3
systemctl --no-pager --full status "$SVC_MANAGER" | sed -n '1,50p' || true

echo "==> Primeira execução do puller OpenCTI (se ativo)..."
if [[ "$ENABLE_OPENCTI" == "yes" && -n "$OPENCTI_TOKEN" ]]; then
  systemctl start wazuh-opencti-puller.service || true
fi

echo "==> DONE."
echo "   - Dashboard: https://$WAZUH_IP/  (user: admin / pass definida)"
echo "   - Scripts agentes: $AGENT_DIR"
echo "   - Backups: $WZ_BACKUP_DIR"
