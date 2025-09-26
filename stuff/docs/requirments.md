# Command-Line Interface for Local LLM Requirements

## Objective

Build a containerized CLI tool (`chat`) that interacts with a custom local language model binary (installed via `bitnet.cpp` in `/home/modeluser/BitNet/build/bin/llama-cli` in the container provided). The tool must allow querying the model using prompts, with optional injection of file content (YAML, Markdown, or plaintext) into the prompt context.

**Primary Use Case**: Analyze and summarize cyber-security artifacts such as CVE records, security configs, or vulnerability reports. Each call to the model must be stateless. If chat history is needed, it must be passed manually.

## Learning Goals

- Understand CLI tool design with support for configuration files and environment variables.
- Understand the benefits of containerization. Explain how does this containerized application work?
- Understand the benefits of using local LLMs v.s. accessing LLMs via commercially available APIs.
- Understand how LLMs use context windows and tokens.
- Understand how LLMs use prompt templates and prompts to get results.
- Measure and manage tokens throughput and response length.

## Deliverables

- Working containerized CLI tool (`chat`) with help page.
- Documentation for usage inside the `README.md`
- Example usage with input files (e.g., CVEs, mitigations, source code, etc.) and configuration files.
- **Write up covering the learning objectives mentioned above in the context of the application you built. Place the write up in [docs/soltution.md](./solution.md).**

## CLI Requirements

```bash
chat [OPTIONS]
```

The tool should:
- Inject the file contents into the model prompt
- Format the full input (system + context + user prompt)
- Execute the model binary
- Display the output to stdout
- Save other statistics about generation or logs to a logging file.

### Example Options

| Option            | Description                                                      |
|-------------------|------------------------------------------------------------------|
| `-f`, `--file`    | One or more files to include in the prompt context               |
| `-p`, `--prompt`  | Main user prompt                                                 |
| `--tokens`        | Maximum tokens in response                                       |
| `--temperature`   | Sampling randomness (0 = deterministic)                          |
| `--system`        | Optional system prompt for role conditioning                     |
| `--config`        | Optional configuration file (`config.toml`, `.env`, etc.)        |

## Examples Usage

### Simple Prompt Example

```
chat -p "What is the CVSS scoring system?"
```

### CVE Context Injection and Mitigation Example

In this example the user passes two `.yaml` files. One contains details about a CVE and the other includes mitigations.

```
chat -f CVE-2025-4455.yaml, mitigation.yaml -p "Explain the risk level and mitigation."
```

### Source Code Analysis Example

Use the local LLM to summarize and assess a vulnerability from source code. In this example the yaml file `code.py` contains some code that could be related to the CVE.

```bash
chat -f code.py -p "CVE-123-1232 is a python vulnerability that occurs when a user imports the tarfile module. Summarize the vulnerability and its impact given the source code.py"
```

### Using Config File Example

```
chat --config config.yaml -p "What services does this firewall rule expose?"
```

## Configuration Support

Support configuration through: `.env (dotenv format)` or `.yaml` files.

### Example .env:
```
MODEL_PATH=./models/bitnet.bin
SYSTEM_PROMPT=You are a cybersecurity assistant.
TEMPERATURE=0.5
MAX_TOKENS=512
```

### Example `config.yaml`:

```yaml
model_path: ./models/bitnet.bin
system_prompt: "You are a cybersecurity assistant."
temperature: 0.5
max_tokens: 512
log_file: ./logs/chat.log
default_prompt: "Summarize the vulnerability and its impact."
```

## Prompt Assembly Logic

Prompt sent to model should be constructed as:

```
[System Prompt, if any]

[File Content(s), if any]

[User Prompt]
```

Think carefully on how you want to handle large files. Some examples include...
- Truncating from the top or bottom.
- Calling the language model multiple times on smaller chunks of the file.
- Provide alerts or logs to user.

## Tips

- I prefer to use the python module `argparse` to make CLIs. https://docs.python.org/3/library/argparse.html
- Use `uv` to manage python package dependencies https://docs.astral.sh/uv/guides/install-python/.
- You are provided a dockerfile! Your tool will need to be COPY into the Dockerfile and invoked via the `chat` command. Start by building the dockerfile and running it interactively. Look through the docker containers file system and determine where the binary lives. The example in `chat.sh` is a good starting point for how to locate the model binary, weights, and format a prompt.