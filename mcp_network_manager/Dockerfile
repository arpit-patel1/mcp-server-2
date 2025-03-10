FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir .

# Copy the application code
COPY . .

# Set default environment variables
ENV MCP_PORT=8000 \
    MCP_TRANSPORT=stdio \
    MCP_INVENTORY=devices.csv \
    MCP_LOG_LEVEL=INFO

# Create a volume for persistent data
VOLUME /app/data

# Expose the port
EXPOSE ${MCP_PORT}

# Run the server
CMD ["sh", "-c", "python -m mcp_network_manager.server --transport ${MCP_TRANSPORT} --port ${MCP_PORT} --inventory ${MCP_INVENTORY} --log-level ${MCP_LOG_LEVEL}"] 