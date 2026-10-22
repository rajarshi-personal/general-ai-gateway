FROM python:3.12-slim
LABEL org.opencontainers.image.authors="Rajarshi"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY general_ai_gateway ./general_ai_gateway
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home general_ai_gateway
COPY examples ./examples
USER 10001
EXPOSE 8080
CMD ["general_ai_gateway", "serve", "--host", "0.0.0.0"]
