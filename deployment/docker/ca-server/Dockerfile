# pancake-ca-server: thin wrapper around upstream smallstep/step-ca.
# Adds a startup script that bootstraps a CA on first run and exposes
# an ACME provisioner with `device-attest-01` for TPM 2.0.
#
# Build (context = deployment/docker/ca-server/):
#   docker build -t pancake-ca-server deployment/docker/ca-server/
#
# Run with named volume (cert state survives container rm):
#   docker volume create pancake-ca-state
#   docker run -d --name pancake-ca-server \
#       -p 8443:8443 \
#       -v pancake-ca-state:/home/step \
#       -e PANCAKE_CA_DNS=ca.pancake.local,localhost,127.0.0.1 \
#       -e PANCAKE_CA_NAME=pancake-demo \
#       pancake-ca-server
#
# What gets exposed:
#   :8443  step-ca's REST API (ACME endpoints under /acme/<provisioner>/)
#
# State written to /home/step on first start:
#   certs/      root + intermediate CA + signing certs
#   secrets/    encrypted keys
#   config/ca.json  ca configuration including the ACME provisioner
#   db/             badger key/value store for issued certs etc
#
# Subsequent starts skip the bootstrap and exec step-ca directly.

FROM smallstep/step-ca:latest
USER root
RUN apk add --no-cache jq
USER step

# Build-time: drop the script into /usr/local/bin (needs root).
USER root
COPY init.sh /usr/local/bin/pancake-ca-init.sh
RUN chmod 0755 /usr/local/bin/pancake-ca-init.sh

# Runtime: drop back to `step` user. Otherwise init.sh writes
# /home/step/{config,certs,secrets,db}/ as root with mode 0600
# and the step-ca daemon (which runs as `step`) can't read its
# own state. Whole-script-as-step keeps perms consistent.
USER step

ENV PANCAKE_CA_DNS=localhost,127.0.0.1
ENV PANCAKE_CA_NAME=pancake-ca

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/pancake-ca-init.sh"]
