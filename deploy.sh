#!/usr/bin/env bash
set -euo pipefail

# ===========================================================================
# Susi Server — EC2 / Lightsail deployment (image-based)
#
# Usage:
#   ./deploy.sh <user@host> [SSH_KEY_PATH] [--staging]
#
# Example:
#   ./deploy.sh ubuntu@3.114.50.38 ~/.ssh/lightsail.pem
#   ./deploy.sh ubuntu@3.114.50.38 ~/.ssh/lightsail.pem --staging
#
# What it does:
#   1. Builds the susi-server Docker image LOCALLY. On-server builds on
#      Lightsail's 1.9 GiB box hit ~1.7 GiB swap and run several times
#      slower than they would on a beefy laptop — and risk OOM. Same
#      pattern fusionhub already uses.
#   2. Saves the image to a gzipped tarball and scps it to the server.
#   3. rsyncs the deployment files (compose files) into /opt/susi.
#   4. Generates .env (SUSI_ADMIN_KEY) + RSA keypair on first deploy.
#   5. `docker load` of the shipped image + `docker compose up -d` (no
#      `--build` flag — uses the loaded image directly).
#
# Local prereqs:
#   - docker (build host), rsync, ssh, openssl, gzip.
#   - On Windows: run from WSL — Git Bash lacks rsync. SSH key must be
#     in WSL's home (~/.ssh/...) with chmod 600.
#
# Remote prereqs:
#   - Docker + Docker Compose v2.
#   - nginx + Let's Encrypt cert for susi.lp-research.com /
#     staging.susi.lp-research.com (terminates TLS, proxies to
#     127.0.0.1:3100 / :3101).
#
# Staging mode (--staging):
#   Deploys to port 3101 with a separate database volume. Use it to
#   test before deploying to production. Both modes ship the *same*
#   image — they differ only in compose file + env + volume.
# ===========================================================================

STAGING=false
POSITIONAL=()
for arg in "$@"; do
    case $arg in
        --staging) STAGING=true ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done

HOST="${POSITIONAL[0]:?Usage: ./deploy.sh <user@host> [ssh-key-path] [--staging]}"
SSH_KEY="${POSITIONAL[1]:-}"
REMOTE_DIR="/opt/susi"
IMAGE_TAG="susi:latest"
IMAGE_TAR="/tmp/susi-image.tar.gz"

if $STAGING; then
    COMPOSE_FILE="docker-compose.staging.yml"
    LABEL="staging"
    PORT=3101
    VOLUME_NAME="susi-data-staging"
else
    COMPOSE_FILE="docker-compose.yml"
    LABEL="production"
    PORT=3100
    VOLUME_NAME="susi-data"
fi

SSH_OPTS="-o StrictHostKeyChecking=accept-new"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

ssh_cmd() { ssh $SSH_OPTS "$HOST" "$@"; }

echo "==> Deploying $LABEL to $HOST"

echo "==> Building $IMAGE_TAG locally"
docker build -t "$IMAGE_TAG" .

echo "==> Saving + compressing image"
docker save "$IMAGE_TAG" | gzip > "$IMAGE_TAR"
ls -lh "$IMAGE_TAR"

echo "==> Shipping image (~$(du -h "$IMAGE_TAR" | cut -f1) over the wire)"
scp $SSH_OPTS "$IMAGE_TAR" "$HOST:/tmp/"

echo "==> Preparing remote directory"
ssh_cmd "sudo mkdir -p $REMOTE_DIR && sudo chown \$(whoami) $REMOTE_DIR"

echo "==> Syncing deployment files (compose)"
# Minimal whitelist — the binary lives inside the image, sources aren't
# needed on the server. Keep the rsync small so the box doesn't spend
# minutes pushing crates/ that no one reads.
if command -v rsync &>/dev/null; then
    rsync -az -e "ssh $SSH_OPTS" \
        docker-compose.yml \
        docker-compose.staging.yml \
        "$HOST:$REMOTE_DIR/"
else
    # Fallback: tar over ssh. Less efficient but works on machines
    # without rsync.
    tar czf - docker-compose.yml docker-compose.staging.yml | \
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
    VOLUME_DIR=\$(docker volume inspect $VOLUME_NAME --format '{{.Mountpoint}}' 2>/dev/null || true)
    if [ -z \"\$VOLUME_DIR\" ]; then
        if [ ! -f $REMOTE_DIR/_private.pem ]; then
            openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $REMOTE_DIR/_private.pem 2>/dev/null
            openssl rsa -in $REMOTE_DIR/_private.pem -pubout -out $REMOTE_DIR/_public.pem 2>/dev/null
            echo 'Generated new RSA 4096-bit keypair.'
        fi
    fi
"

echo "==> Loading image + starting $LABEL container"
ssh_cmd "
    set -e
    cd $REMOTE_DIR

    echo '  Loading $IMAGE_TAG from /tmp/susi-image.tar.gz...'
    gunzip -c /tmp/susi-image.tar.gz | docker load
    rm -f /tmp/susi-image.tar.gz

    docker compose -f $COMPOSE_FILE up -d

    if [ -f $REMOTE_DIR/_private.pem ]; then
        VOLUME_DIR=\$(docker volume inspect $VOLUME_NAME --format '{{.Mountpoint}}')
        sudo cp $REMOTE_DIR/_private.pem \$VOLUME_DIR/private.pem
        sudo cp $REMOTE_DIR/_public.pem \$VOLUME_DIR/public.pem
        sudo chown 1000:1000 \$VOLUME_DIR/private.pem \$VOLUME_DIR/public.pem
        rm $REMOTE_DIR/_private.pem $REMOTE_DIR/_public.pem

        docker compose -f $COMPOSE_FILE restart
        echo 'Keys copied into volume and server restarted.'
    fi
"

# Clean up local tarball — it's idempotent to regenerate next deploy.
rm -f "$IMAGE_TAR"

echo ""
echo "==> Deployment complete! ($LABEL)"
echo "    Server:    http://$HOST:$PORT"
echo "    Dashboard: http://$HOST:$PORT"
echo "    Health:    http://$HOST:$PORT/health"
echo ""
echo "    To check logs:  ssh $SSH_OPTS $HOST 'cd $REMOTE_DIR && docker compose -f $COMPOSE_FILE logs -f'"
echo "    To stop:        ssh $SSH_OPTS $HOST 'cd $REMOTE_DIR && docker compose -f $COMPOSE_FILE down'"
echo ""
if $STAGING; then
    echo "    This is the STAGING instance. Once verified, deploy to production without --staging."
else
    echo "    Don't forget to open port $PORT in your AWS Security Group!"
fi
