FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    tshark tcpdump iproute2 \
    less nano wget curl unzip jq git ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir pandas texttable
COPY tools/analyze_timeline.py /usr/local/bin/analyze_timeline.py
RUN chmod +x /usr/local/bin/analyze_timeline.py
WORKDIR /workspace
CMD ["bash"]
