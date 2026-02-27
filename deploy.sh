#!/usr/bin/env bash
set -euo pipefail

# ===========================================================================
# Susi Server — EC2 Deployment Script
#
# Usage:
#   ./deploy.sh <EC2_HOST> [SSH_KEY_PATH]
#
# Example:
#   ./deploy.sh ubuntu@54.123.45.67 ~/.ssh/my-key.pem
#
# Prerequisites on your EC2 instance:
#   - Docker & Docker Compose installed
#   - SSH access configured
#
# What this script does:
#   1. Copies the project to the EC2 instance
#   2. Generates a private key if none exists on the server
#   3. Builds and starts the container
# ===========================================================================

HOST="${1:?Usage: ./deploy.sh <user@host> [ssh-key-path]}"
SSH_KEY="${2:-}"
REMOTE_DIR="/opt/susi"

SSH_OPTS="-o StrictHostKeyChecking=accept-new"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

ssh_cmd() { ssh $SSH_OPTS "$HOST" "$@"; }
scp_cmd() { scp $SSH_OPTS "$@"; }

echo "==> Preparing remote directory on $HOST"
ssh_cmd "sudo mkdir -p $REMOTE_DIR && sudo chown \$(whoami) $REMOTE_DIR"

echo "==> Syncing project files"
# Use rsync if available, otherwise fall back to scp
if command -v rsync &>/dev/null; then
    rsync -az --exclude target --exclude '*.db' --exclude '*.pem' \
          --exclude keys --exclude license.json --exclude .git \
          -e "ssh $SSH_OPTS" \
          ./ "$HOST:$REMOTE_DIR/"
else
    # Tar + pipe approach as fallback
    tar czf - --exclude=target --exclude='*.db' --exclude='*.pem' \
              --exclude=keys --exclude=license.json --exclude=.git . | \
        ssh_cmd "cd $REMOTE_DIR && tar xzf -"
fi

echo "==> Setting up .env file"
ssh_cmd "
    if [ ! -f $REMOTE_DIR/.env ]; then
        ADMIN_KEY=\$(openssl rand -hex 32)
        echo \"SUSI_ADMIN_KEY=\$ADMIN_KEY\" > $REMOTE_DIR/.env
        chmod 600 $REMOTE_DIR/.env
        echo \"Generated new admin key: \$ADMIN_KEY\"
        echo \"SAVE THIS KEY — you will need it for admin API access.\"
    else
        echo '.env already exists, keeping existing admin key.'
    fi
"

echo "==> Generating RSA keypair if not present"
ssh_cmd "
    # Ensure the docker volume data dir exists
    VOLUME_DIR=\$(docker volume inspect susi-data --format '{{.Mountpoint}}' 2>/dev/null || true)
    if [ -z \"\$VOLUME_DIR\" ]; then
        # Volume will be created on first run; generate keys in a temp spot
        # and copy them into the volume after compose up
        if [ ! -f $REMOTE_DIR/_private.pem ]; then
            openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $REMOTE_DIR/_private.pem 2>/dev/null
            openssl rsa -in $REMOTE_DIR/_private.pem -pubout -out $REMOTE_DIR/_public.pem 2>/dev/null
            echo 'Generated new RSA 4096-bit keypair.'
        fi
    fi
"

echo "==> Building and starting container"
ssh_cmd "
    set -e
    cd $REMOTE_DIR

    # Build and start
    docker compose up -d --build

    # If we generated keys earlier, copy them into the volume
    if [ -f $REMOTE_DIR/_private.pem ]; then
        VOLUME_DIR=\$(docker volume inspect susi-data --format '{{.Mountpoint}}')
        sudo cp $REMOTE_DIR/_private.pem \$VOLUME_DIR/private.pem
        sudo cp $REMOTE_DIR/_public.pem \$VOLUME_DIR/public.pem
        sudo chown 1000:1000 \$VOLUME_DIR/private.pem \$VOLUME_DIR/public.pem
        rm $REMOTE_DIR/_private.pem $REMOTE_DIR/_public.pem

        # Restart so the server picks up the key
        docker compose restart
        echo 'Keys copied into volume and server restarted.'
    fi
"

echo ""
echo "==> Deployment complete!"
echo "    Server:    http://$HOST:3100"
echo "    Dashboard: http://$HOST:3100"
echo "    Health:    http://$HOST:3100/health"
echo ""
echo "    To check logs:  ssh $SSH_OPTS $HOST 'cd $REMOTE_DIR && docker compose logs -f'"
echo "    To stop:        ssh $SSH_OPTS $HOST 'cd $REMOTE_DIR && docker compose down'"
echo ""
echo "    Don't forget to open port 3100 in your AWS Security Group!"
