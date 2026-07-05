FROM python:3.12-slim

RUN pip install --no-cache-dir mrtparse

COPY tests/parsers/runners/mrtparse_check.py /usr/local/bin/mrtparse_check.py
COPY tests/parsers/runners/routes_mrtparse_check.py /usr/local/bin/routes_mrtparse_check.py

ENTRYPOINT ["python", "/usr/local/bin/mrtparse_check.py"]
