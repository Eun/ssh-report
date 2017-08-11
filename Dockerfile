FROM alpine:latest

MAINTAINER Edward Muller <edward@heroku.com>

WORKDIR "/opt"

ADD .docker_build/ssh-report /opt/bin/ssh-report
ADD ./templates /opt/templates
ADD ./static /opt/static

CMD ["/opt/bin/ssh-report"]