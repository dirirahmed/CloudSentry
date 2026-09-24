#!/usr/bin/env bash
# Installs or updates CloudSentry on an Ubuntu Server 24.04 EC2 instance.
# Run from a Session Manager shell:  sudo bash /opt/cloudsentry/deploy/setup-ec2.sh
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/dirirahmed/CloudSentry.git}"
APP_DIR=/opt/cloudsentry
WEB_ROOT=/var/www/cloudsentry

apt-get update
apt-get install -y git nginx python3-venv curl ca-certificates

# Vite needs Node.js 20.19+ or 22.12+; Ubuntu 24.04's packaged Node is older.
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

id -u cloudsentry >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin cloudsentry

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone "$REPO_URL" "$APP_DIR"
fi

python3 -m venv "$APP_DIR/backend/.venv"
"$APP_DIR/backend/.venv/bin/pip" install --upgrade pip
"$APP_DIR/backend/.venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt"

cd "$APP_DIR/frontend"
if [ -f package-lock.json ]; then npm ci; else npm install; fi
npm run build
rm -rf "$WEB_ROOT"
cp -r dist "$WEB_ROOT"

[ -f /etc/cloudsentry.env ] || cp "$APP_DIR/deploy/cloudsentry.env.example" /etc/cloudsentry.env
cp "$APP_DIR/deploy/cloudsentry.service" /etc/systemd/system/cloudsentry.service
cp "$APP_DIR/deploy/nginx.conf" /etc/nginx/sites-available/cloudsentry
ln -sf /etc/nginx/sites-available/cloudsentry /etc/nginx/sites-enabled/cloudsentry
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable --now cloudsentry
systemctl restart cloudsentry
nginx -t
systemctl reload nginx

echo "CloudSentry is running. Edit /etc/cloudsentry.env, then: sudo systemctl restart cloudsentry"
