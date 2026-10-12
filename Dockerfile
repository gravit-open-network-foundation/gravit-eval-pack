FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git make && rm -rf /var/lib/apt/lists/*
WORKDIR /pack
COPY Makefile ./
COPY eval ./eval
RUN make deps PYTHON=python
CMD ["make", "eval", "PYTHON=python"]
