####################
# Base-Build
####################

FROM ubuntu:16.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

# Install build tools
RUN apt-get update && apt-get install -y \
    gcc \
    gcc-multilib \
    libc6 \
    libc6-dev \
    net-tools \
    git \
    autoconf \
    automake \
    libtool \
    pkg-config \
    make \
    checkinstall \
    build-essential \
    git \
    zlib1g-dev \
    wget

# Install libraries
RUN apt-get install -y \
    libhiredis-dev \
    libmysqlclient-dev \
    libjansson-dev

# Install updated OpenSSL manually
WORKDIR /usr/local/src
RUN wget https://www.openssl.org/source/openssl-1.1.1n.tar.gz --no-check-certificate
RUN tar -xf openssl-1.1.1n.tar.gz
WORKDIR /usr/local/src/openssl-1.1.1n
RUN ./config && make && make install

RUN apt-get -y upgrade

# Install libjwt manually
# WORKDIR /usr/local/src
# RUN git clone https://github.com/benmcollins/libjwt.git --branch v1.12.0 --single-branch
COPY ./lib/libjwt.tar.gz /usr/local/src/libjwt.tar.gz
WORKDIR /usr/local/src
RUN tar -xf libjwt.tar.gz
WORKDIR /usr/local/src/libjwt
RUN autoreconf -i && \
    ./configure && \
    make && \
    checkinstall --pkgname=libjwt --pkgversion="1.12.0" --default

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

####################
# Build-Auth
####################

FROM base as build-auth

COPY ./auth /auth
WORKDIR /auth
RUN make clean
RUN make CFLAGS='-z execstack -fno-stack-protector -z norelro -g -O0'

####################
# Build-Chat
####################

FROM base as build-chat

COPY ./chat /chat
WORKDIR /chat
RUN make clean
RUN make CFLAGS='-z execstack -fno-stack-protector -z norelro -g -O0'

####################
# Base-Server
####################

FROM base AS base-server

ENV DEBIAN_FRONTEND=noninteractive

ENV MYSQL_ROOT_PASSWORD=password \
    MYSQL_DATABASE=auth \
    MYSQL_USER=user \
    MYSQL_PASSWORD=password

RUN apt-get update
RUN apt-get install -y redis-server mysql-server
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Initialize the MySQL data directory
COPY setup_mysql.sh /setup_mysql.sh
RUN service mysql start && \
    sleep 5 && \
    sh /setup_mysql.sh && \
    service mysql stop

####################
# Execution
####################

FROM base-server

EXPOSE 5000

COPY ./start.sh /start.sh
RUN chmod +x /start.sh
COPY --from=build-auth /auth /auth
COPY --from=build-chat /chat /chat

CMD ["/start.sh"]
