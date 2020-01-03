FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install sshfs -y

RUN useradd sshfs
RUN groupadd fuse
RUN usermod -a -G fuse sshfs

USER sshfs

RUN mkdir logs
