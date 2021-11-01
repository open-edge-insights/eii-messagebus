ARG ALPINE_VERSION
FROM alpine:${ALPINE_VERSION}

ARG USER="builder"
RUN apk add alpine-sdk git sudo gcc g++ make cmake bash

RUN adduser -D $USER \
        && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
        && chmod 0440 /etc/sudoers.d/$USER \
        && addgroup $USER abuild

RUN mkdir -p /var/cache/distfiles \
        && chgrp abuild /var/cache/distfiles \
        && chmod g+w /var/cache/distfiles

COPY ./build.sh /bin/
RUN chmod +x /bin/build.sh

RUN mkdir /package && chown $USER:$USER /package

USER ${USER}
RUN abuild-keygen -a -i -n

WORKDIR /package

CMD ["/bin/bash", "/bin/build.sh"]
