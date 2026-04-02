FROM python:3.12.8-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["threatlens"]
CMD ["--help"]
