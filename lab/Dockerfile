# Vulnerable GNU InetUtils telnetd lab target
# FOR AUTHORIZED SECURITY TESTING ONLY - never expose to public networks
#
# Builds GNU inetutils 2.5 telnetd (vulnerable to CVE-2026-24061 & CVE-2026-32746)
# Runs telnetd on port 23 inside an isolated container.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    login \
    openbsd-inetd \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Build vulnerable GNU inetutils 2.5 from source
RUN wget -q https://ftp.gnu.org/gnu/inetutils/inetutils-2.5.tar.xz \
    && tar xf inetutils-2.5.tar.xz \
    && cd inetutils-2.5 \
    && ./configure --prefix=/usr/local --disable-clients \
    && make -j$(nproc) \
    && make install \
    && cd / && rm -rf inetutils-2.5 inetutils-2.5.tar.xz

# Create a test user for the lab
RUN useradd -m -s /bin/bash labuser && echo "labuser:labpass123" | chpasswd

# Configure inetd to serve telnetd
RUN echo "telnet stream tcp nowait root /usr/local/libexec/telnetd telnetd" >> /etc/inetd.conf

EXPOSE 23

CMD ["/usr/sbin/inetd", "-d"]
