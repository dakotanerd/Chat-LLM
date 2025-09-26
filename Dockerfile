##############
# Build stage
##############
FROM ubuntu:24.04 AS builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    cmake \
    g++ \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    ccache \
    build-essential \
    lsb-release \
    software-properties-common \
    gnupg \
    clang && \
    rm -rf /var/lib/apt/lists/*

# Install uv using the installer
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

# Clone BitNet and setup virtual environment
WORKDIR /BitNet
RUN git clone --recursive https://github.com/microsoft/BitNet.git .
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install pip && \
    uv pip install PyYAML python-dotenv -r requirements.txt --index-strategy unsafe-best-match && \
    mkdir -p models/BitNet-b1.58-2B-4T

# Download the model
ADD https://huggingface.co/microsoft/bitnet-b1.58-2B-4T-gguf/resolve/main/ggml-model-i2_s.gguf \
    models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf

# Setup BitNet environment
RUN ./.venv/bin/python setup_env.py -md models/BitNet-b1.58-2B-4T -q i2_s


########################
# Final stage
########################
FROM ubuntu:24.04

# Install Python and create user
RUN apt-get update && \
    apt-get install -y python3-venv python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m modeluser

# Copy uv from builder
COPY --from=builder /root/.local/bin/uv /usr/local/bin/uv
ENV PATH="/home/modeluser/.local/bin:$PATH"

# Copy BitNet (base code + venv) from builder
COPY --from=builder --chown=modeluser:modeluser /BitNet/ /home/modeluser/BitNet/

# Copy required shared libraries
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/src/libllama.so /usr/lib/
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/ggml/src/libggml.so /usr/lib/

# Run ldconfig as root BEFORE switching to modeluser
RUN ldconfig

# Copy all local project files into BitNet (ensures chat folder is included)
COPY --chown=modeluser:modeluser . /home/modeluser/BitNet/

# Ensure working directory
WORKDIR /home/modeluser/BitNet

# Create wrapper script for chat
RUN echo '#!/bin/sh' > /usr/local/bin/chat && \
    echo 'exec /home/modeluser/BitNet/.venv/bin/python /home/modeluser/BitNet/chat/chat.py "$@"' >> /usr/local/bin/chat && \
    chmod +x /usr/local/bin/chat

# Add a welcome banner for the user
RUN echo '\
echo "==============================================="\n\
echo "Welcome to the BitNet container!"\n\
echo "Use the chat command to interact with the AI."\n\
echo "Examples: chat -p '\''Hello AI'\'' , chat -f tests"\n\
echo "==============================================="\n\
' >> /home/modeluser/.bashrc

# Switch to modeluser
USER modeluser

# Default entry
CMD ["/bin/bash"]
