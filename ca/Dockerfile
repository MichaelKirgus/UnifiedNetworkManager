# UNM Certificate Authority — a thin wrapper around smallstep/certificates
# (step-ca, Apache 2.0). The base image ships the `step` CLI + step-ca binary;
# this layer adds ONLY the first-boot PKI bootstrap and pre-creates the two
# mount points so named volumes inherit `step` ownership:
#
#   /pki      CA-only volume — root/intermediate certs + intermediate key.
#             Mounted on unm-ca ONLY. The API never sees signing keys.
#   /data/ca  shared config volume — ca.json (rendered by the UNM API from
#             global settings) + step-ca's embedded Badger state DB.
#
# See docs/PLUGIN-DEVELOPMENT.md §"TLS & enrollment" and api/src/ca/.
FROM smallstep/step-ca:0.30.2

# NOTE: the base image runs as non-root user `step` (uid 1000). We switch to
# root for one layer to set permissions + pre-create the mount points so fresh
# named volumes inherit step-owned directories, then drop back to step.
USER root
COPY ca/entrypoint.sh /entrypoint-unm.sh
RUN chmod 755 /entrypoint-unm.sh \
    && mkdir -p /pki /data/ca \
    && chown step:step /pki /data/ca
USER step

ENTRYPOINT ["/bin/sh", "/entrypoint-unm.sh"]
