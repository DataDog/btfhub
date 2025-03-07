FROM registry.access.redhat.com/rhel7:latest

ARG VAULT_VERSION
ARG VAULT_SHA256_LINUX_AMD64

# rhel7 has no repos by default, so we use EPEL which doesn't require a subscription
# unzip is not available, so we install p7zip for zip extraction
RUN curl -LO https://dl.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/e/epel-release-7-14.noarch.rpm \
  && yum install -y ./epel-release-7-14.noarch.rpm \
  && yum update \
  && yum install -y p7zip

# Install vault: https://github.com/hashicorp/vault/blob/main/CHANGELOG.md https://releases.hashicorp.com/vault
RUN curl -LO "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" \
  && echo "${VAULT_SHA256_LINUX_AMD64}" vault_${VAULT_VERSION}_linux_amd64.zip | sha256sum --check \
  && 7za e -o/usr/bin vault_${VAULT_VERSION}_linux_amd64.zip \
  && rm vault_${VAULT_VERSION}_linux_amd64.zip

RUN yum erase -y epel-release
