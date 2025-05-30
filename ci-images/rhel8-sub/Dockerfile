FROM registry.access.redhat.com/ubi8/ubi:latest

ARG TARGETARCH
ARG VAULT_VERSION
ARG VAULT_SHA256_LINUX_AMD64
ARG VAULT_SHA256_LINUX_ARM64

RUN yum install -y unzip wget

# Install vault: https://github.com/hashicorp/vault/blob/main/CHANGELOG.md https://releases.hashicorp.com/vault
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
  wget -nv -O /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" \
    && echo "${VAULT_SHA256_LINUX_AMD64}" /tmp/vault.zip | sha256sum --check \
    && unzip -o /tmp/vault.zip -d /usr/bin vault \
    && rm /tmp/vault.zip \
; elif [ "${TARGETARCH}" = "arm64" ]; then \
  wget -nv -O /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" \
      && echo "${VAULT_SHA256_LINUX_ARM64}" /tmp/vault.zip | sha256sum --check \
      && unzip -o /tmp/vault.zip -d /usr/bin vault \
      && rm /tmp/vault.zip \
; fi
