# Use Python 3.9 as base image for better compatibility
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    wireless-tools \
    aircrack-ng \
    nmap \
    iputils-ping \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Set permissions for the menu script
RUN chmod +x security_tools_menu.py

# Create a non-root user
RUN useradd -m securityuser && \
    echo "securityuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to non-root user
USER securityuser

# Set the entrypoint
ENTRYPOINT ["python3", "security_tools_menu.py"] 