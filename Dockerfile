FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md requirements.txt ./
COPY dispatch ./dispatch
COPY dispatch-server.py ./
RUN pip install --no-cache-dir .

EXPOSE 8080 8000
VOLUME ["/app/dispatch/data"]
ENTRYPOINT ["dispatch-server"]
CMD ["--http", "--bind-host", "0.0.0.0", "--admin-port", "8080", "--client-port", "8000"]
