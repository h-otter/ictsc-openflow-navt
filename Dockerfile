FROM python:latest

MAINTAINER h-otter <h-otter@outlook.jp>

WORKDIR /root/

RUN pip install --no-cache-dir --upgrade --ignore-installed ryu

ADD navt.py /root/

CMD ["ryu-manager", "navt.py"]
