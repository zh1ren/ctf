FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15

ENV user acs_ctf

RUN apt update
RUN apt-get install -y socat

RUN useradd $user

COPY ./deploy/flag /home/$user/flag
COPY ./deploy/prob /home/$user/prob

RUN chown -R root:$user /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/prob

RUN chmod 755 /home/$user/prob
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE 10002
CMD socat TCP-LISTEN:10002,reuseaddr,fork EXEC:/home/$user/prob