FROM python:3.12-slim
WORKDIR /app
COPY mcp_server.py /app/mcp_server.py
COPY server.json /app/server.json
COPY README.md /app/README.md
RUN pip install --no-cache-dir mcp uvicorn starlette
ENTRYPOINT ["python3", "/app/mcp_server.py"]
CMD ["--http", "--port", "8138"]
