FROM ubuntu:16.04
RUN apt-get update
RUN apt-get install -y python python-pip libleveldb1v5 libleveldb-dev
COPY requirements.txt /tmp/
RUN pip install --requirement /tmp/requirements.txt
RUN mkdir /tmp/py-project
COPY docker-wait.sh /tmp/loopme.sh
RUN chmod +x /tmp/loopme.sh
ENV PYTHONUNBUFFERED 1
CMD ["/tmp/loopme.sh"]