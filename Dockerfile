FROM python:3.6.7-slim-jessie

RUN rm /etc/apt/sources.list
RUN echo "deb http://archive.debian.org/debian/ jessie main" | tee -a /etc/apt/sources.list
RUN echo "deb-src http://archive.debian.org/debian/ jessie main" | tee -a /etc/apt/sources.list
RUN echo "Acquire::Check-Valid-Until false;" | tee -a /etc/apt/apt.conf.d/10-nocheckvalid
RUN echo 'Package: *\nPin: origin "archive.debian.org"\nPin-Priority: 500' | tee -a /etc/apt/preferences.d/10-archive-pin
RUN apt-get update && apt-get install -y \
        git \
        libboost-all-dev \
        libgmp3-dev \
        libprocps-dev \
        g++ \
        gcc \
        libxslt-dev \
        vim \
        cmake \
        libssl-dev \
        pkg-config \
        curl \
        sudo

# Install a recent version of nodejs
RUN curl -sL https://deb.nodesource.com/setup_10.x | sudo bash - && sudo apt-get install -y nodejs
RUN npm install -g truffle ganache-cli

# Configue the environment for gRPC
RUN apt-get install -y \
        build-essential \
        autoconf \
        libtool
RUN git clone -b $(curl -L https://grpc.io/release) https://github.com/grpc/grpc /var/local/git/grpc
RUN cd /var/local/git/grpc && git submodule update --init --recursive
RUN cd /var/local/git/grpc/third_party/protobuf && ./autogen.sh && ./configure --prefix=/usr && make -j12 && make check && make install && make clean
RUN cd /var/local/git/grpc && make install

# Copy the project in the docker container
COPY . /home/zeth

WORKDIR /home/zeth

CMD ["/bin/bash"]
