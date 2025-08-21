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
    clang 

# Install uv using the installer
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
# Add uv to PATH
ENV PATH="/root/.local/bin/:$PATH"

# Install bitnet from source + adding dependencies outside of the requirements.txt like  PyYAML python-dotenv
WORKDIR /
RUN git clone --recursive https://github.com/microsoft/BitNet.git
WORKDIR /BitNet
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install pip && \
    uv pip install PyYAML python-dotenv -r requirements.txt --index-strategy unsafe-best-match && \
    mkdir -p models/BitNet-b1.58-2B-4T

# Download the model
ADD https://huggingface.co/microsoft/bitnet-b1.58-2B-4T-gguf/resolve/main/ggml-model-i2_s.gguf models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf

# Setup bitnet environment
RUN ./.venv/bin/python setup_env.py -md models/BitNet-b1.58-2B-4T -q i2_s

########################
# Final stage
########################
FROM ubuntu:24.04

# Install Python and create user in final stage
RUN apt-get update && \
    apt-get install -y python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    useradd modeluser

# --- START: New Code ---
# Copy uv from the builder stage and add it to the PATH
COPY --from=builder /root/.local/bin/uv /usr/local/bin/uv
ENV PATH="/home/modeluser/.local/bin:$PATH"
# --- END: New Code ---

# Copy the application and its virtual environment
COPY --from=builder --chown=modeluser:modeluser /BitNet/ /home/modeluser/BitNet/

# Copy required shared libraries
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/src/libllama.so /usr/lib/
COPY --from=builder /BitNet/build/3rdparty/llama.cpp/ggml/src/libggml.so /usr/lib/

# Copy the chat script
COPY chat.py /home/modeluser/BitNet/chat.py

WORKDIR /home/modeluser/BitNet

# Make the chat script executable
RUN chmod +x /home/modeluser/BitNet/chat.py

# --- START: Modified Code ---
# Create a wrapper script at /usr/local/bin/chat that executes chat.py
# with the correct Python interpreter from the virtual environment.
RUN echo '#!/bin/sh' > /usr/local/bin/chat && \
    echo 'exec /home/modeluser/BitNet/.venv/bin/python /home/modeluser/BitNet/chat.py "$@"' >> /usr/local/bin/chat && \
    chmod +x /usr/local/bin/chat
# --- END: Modified Code ---

# Add a welcome banner for modeluser
RUN echo '\
echo "==============================================="\n\
echo "Welcome to the BitNet container!"\n\
echo "Use the chat command to interact with the AI."\n\
echo "Examples: chat -p '\''Hello AI'\'' , chat -h"\n\
echo "==============================================="\n\
' >> /home/modeluser/.bashrc

USER modeluser


CMD ["/bin/bash"]
