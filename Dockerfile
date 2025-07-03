FROM pspdev/pspdev:latest

LABEL maintainer="xeonliu"

LABEL description="Translation Project \
for PSP Evangelion 2: Another Cases."

# Install dependencies

# Install curl
RUN apk add curl
# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /app

COPY pyproject.toml /app

# Install dependencies
RUN source $HOME/.local/bin/env && uv sync

# 使用 bash 并在启动时运行 source
ENTRYPOINT [ "bash", "-c", "source $HOME/.local/bin/env && exec bash" ]