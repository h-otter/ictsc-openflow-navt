FROM python:latest

MAINTAINER h-otter <h-otter@outlook.jp>

WORKDIR /opt/navt

RUN pip install --no-cache-dir --upgrade --ignore-installed ryu

ADD navt.py /opt/navt

CMD ["ryu-manager", "navt.py"]
