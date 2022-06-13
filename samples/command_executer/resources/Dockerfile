FROM ubuntu:latest
  COPY command-executer .
  RUN apt-get update && apt-get install -y \
      apt-utils kmod iperf3 gcc mono-mcs make git && \
      git clone https://github.com/stefano-garzarella/iperf-vsock && \
      cd iperf-vsock && \
        mkdir build && \
        cd build && \
        ../configure && \
        make
  CMD ./command-executer listen --port 5005
