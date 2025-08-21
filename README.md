# Chat

The chat tool allows us to interact with a language model inside of the GitLab runners with no special hardware! It is based on [Microsoft's BitNet Project](https://github.com/microsoft/BitNet?tab=readme-ov-file#build-from-source) and uses the [BitNet-b1.58-2B-4T](https://huggingface.co/microsoft/BitNet-b1.58-2B-4T) model with special [terenary quantization](https://arxiv.org/abs/2502.11880) to run efficently on CPU.

### :warning: Warning

**This is an experimental tool container.** Usage of this tool container is **at your own risk**. Language models can return **unexpected or offensive content and present various model security and data privacy concerns**.

## Usage

### Build

Building the image locally requires the BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf file to be downloaded. The model weights are stored in this projects model registry. The [gitlab-ci.yml](/.gitlab-ci.yml) contains the job `pre-build-get-model` which provides an example of how to retreive the model weights with `curl`. Once you have the model weights, you can build the image with the following command:

```
docker build . -t chat
```

### Run

If you've build the container locally, you can run the `chat` command with a prompt. For example,

```
docker run -it chat:latest chat "What is a CVE?"
```

The [gitlab-ci.yml](/.gitlab-ci.yml) also contains the job `post-build-test` which provides an example using the container in a CI/CD pipeline.
