# Use the custom base image
FROM lukerobertson19/base-os:latest

# OCI labels for the image
LABEL org.opencontainers.image.title="AI Assistant plugin: Cloud Flare"
LABEL org.opencontainers.image.description="A plugin to receive alerts from Cloud Flare, filter and parse them, and log them to the AI assistant logging service for handling."
LABEL org.opencontainers.image.base.name="lukerobertson19/base-os:latest"
LABEL org.opencontainers.image.source="https://github.com/LukeRoberson/Cloudflare-Plugin"
LABEL org.opencontainers.image.version="1.0.0"

# Custom Labels for the image
LABEL net.networkdirection.healthz="http://localhost:5100/api/health"
LABEL net.networkdirection.plugin.name="CloudFlare"

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . .

# Start the application using uWSGI
CMD ["uwsgi", "--ini", "uwsgi.ini"]
