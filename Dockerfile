FROM docker:20.10.21-dind

WORKDIR /

RUN apk add --no-cache \
    curl \
    python3
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py
RUN pip install --upgrade \
    logrusformatter \
    docker \
    humanize \
    six

COPY ./push-stats.py /push-stats.py

ENTRYPOINT ["python3", "./push-stats.py"]
