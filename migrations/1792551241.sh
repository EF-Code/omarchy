echo "Distrust the emSign root affected by the eMudhra key compromise"

# Another user, or ca-certificates-mozilla 3.131.1, may already have removed the root from the TLS bundle.
tls_bundle=/etc/ca-certificates/extracted/tls-ca-bundle.pem

if [[ ! -s $tls_bundle ]] || grep -qxF "# emSign ECC Root CA - G3" "$tls_bundle"; then
  sudo bash -euo pipefail "$OMARCHY_PATH/install/config/block-emsign-root.sh"
fi
