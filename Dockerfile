FROM python:3.14.5-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["threatlens"]
CMD ["--help"]
