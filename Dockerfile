FROM vijayee/ipfs
MAINTAINER Vijayee Kulkaa <vijayee.kulkaa@hushmail.com>
USER root
ENV IPFS_PATH /data/ipfs

EXPOSE 4001 5001 8080
# 4001 = Swarm, 5001 = API, 8080 = HTTP transport

VOLUME /data/ipfs


ADD /main/main ./account
ADD /IPFSService/container_daemon container_daemon
RUN cp container_daemon /usr/local/bin/start_account && \
    chmod 755 /usr/local/bin/start_account

USER ipfs

ENTRYPOINT ["/usr/local/bin/start_account"]
#CMD ["-host"]

# build:    docker build -t go-ipfs .
# run:      docker run -p 4001:4001 -p 5001:5001 go-ipfs:latest
# run:      docker run -p 8080:8080 -p 4001:4001 -p 5001:5001 go-ipfs:latest
