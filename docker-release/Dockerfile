FROM ubuntu:16.04
RUN apt-get update
RUN apt-get install -y python python-pip libleveldb1v5 libleveldb-dev
COPY docker-wait.sh /tmp/loopme.sh
RUN chmod +x /tmp/loopme.sh
COPY requirements.txt /tmp/
RUN pip install --requirement /tmp/requirements.txt

# This instructions create an own image
RUN apt-get install -y wget unzip
WORKDIR /tmp
RUN wget -o /dev/null https://github.com/furio/py-google-safelist/archive/master.zip -O temp.zip; unzip temp.zip; rm temp.zip
RUN mv py-google-safelist-master py-project
COPY config.cfg /tmp/py-project/config.cfg
WORKDIR /tmp/py-project
RUN mkdir save
CMD ["python", "main.py"]