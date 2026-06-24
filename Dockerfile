FROM python:3.12-slim

LABEL maintainer="Toc Consulting <tarek@tocconsulting.fr>"
LABEL description="AWS ECS/EKS container security scanner with compliance mapping for AWS FSBP, CIS EKS, PCI-DSS, HIPAA, SOC 2, ISO, GDPR, and NIST"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY ecs_eks_security_scanner/ ./ecs_eks_security_scanner/

# Install the package
RUN pip install --no-cache-dir .

# Create output directory
RUN mkdir -p /app/output

# Set default output directory
ENV ECS_EKS_SCANNER_OUTPUT_DIR=/app/output

# Default entrypoint
ENTRYPOINT ["ecs-eks-security-scanner"]

# Default command (show help)
CMD ["--help"]
