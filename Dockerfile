FROM alpine:latest

COPY certchecker.linux64 /usr/local/bin/certchecker
USER nobody
CMD /usr/local/bin/certchecker