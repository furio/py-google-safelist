FROM ubuntu:16.04
RUN apt-get update
RUN apt-get install -y python python-pip libleveldb1v5 libleveldb-dev
RUN mkdir /tmp/py-project
COPY docker-wait.sh /tmp/loopme.sh
RUN chmod +x /tmp/loopme.sh
COPY requirements.txt /tmp/
RUN pip install --requirement /tmp/requirements.txt
CMD ["/tmp/loopme.sh"]