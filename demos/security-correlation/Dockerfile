FROM registry.access.redhat.com/ubi9/python-312:latest

USER 0

RUN dnf install -y --setopt=install_weak_deps=0 \
        java-17-openjdk-headless \
        gcc \
        python3.12-devel \
    && dnf clean all

RUN pip3.12 install --no-cache-dir \
        'ansible-core~=2.20.7' \
        ansible-runner \
        ansible-rulebook \
        aiokafka \
    && mkdir -p /usr/share/ansible/collections \
    && ansible-galaxy collection install 'ansible.eda:2.12.1' -p /usr/share/ansible/collections

COPY collections/ansible_collections/security /usr/share/ansible/collections/ansible_collections/security

ENV ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections
ENV JAVA_HOME=/usr/lib/jvm/jre-17-openjdk
ENV PATH="/usr/lib/jvm/jre-17-openjdk/bin:${PATH}"

WORKDIR /
USER 1001
