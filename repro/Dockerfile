FROM python:3.10 as build

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y libpcap-dev mtr-tiny fping && rm -rf /var/lib/apt/lists/*
RUN setcap 'cap_net_raw+ep' /usr/local/bin/python3.10

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

CMD [ "repro" ]

