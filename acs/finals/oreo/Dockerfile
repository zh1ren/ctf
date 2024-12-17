FROM ubuntu:24.04

RUN apt-get update -y
RUN apt-get install socat strace -y

ENV user oreo
ENV binary oreo
ENV port 12345

RUN useradd -m $user
RUN chown root:$user /home/$user

COPY --chown=root:$user flag /home/$user
RUN chmod 440 /home/$user/flag

COPY --chown=root:$user $binary /home/$user
RUN chmod 755 /home/$user/$binary

COPY --chown=root:$user run.sh /home/$user
RUN chmod 755 /home/$user/run.sh

WORKDIR /home/$user
CMD socat -T 3000 TCP-LISTEN:$port,reuseaddr,fork EXEC:/home/oreo/run.sh
USER $user
EXPOSE $port

