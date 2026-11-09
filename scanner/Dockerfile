FROM golang:1.27-alpine AS pdtools

ENV CGO_ENABLED=0

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


FROM python:3.12-slim

WORKDIR /app

# Install scanner dependencies, but NOT Debian's outdated Nikto package.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    perl \
    git \
    ca-certificates \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libxml-writer-perl \
    libxml-libxml-perl \
    libjson-perl \
    libdigest-perl-md5-perl \
    && git clone --depth 1 --branch 2.6.1 \
        https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=pdtools /go/bin/httpx /usr/local/bin/httpx
COPY --from=pdtools /go/bin/nuclei /usr/local/bin/nuclei

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY ./app ./app

RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /var/lib/sentinel/results \
    && mkdir -p /home/scanner/.config/nuclei \
    && chown -R scanner:scanner /var/lib/sentinel /home/scanner

ENV HOME=/home/scanner

USER scanner

EXPOSE 8100

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
