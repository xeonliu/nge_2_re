FROM pspdev/pspdev:latest

LABEL maintainer="xeonliu"

LABEL description="Translation Project \
for PSP Evangelion 2: Another Cases."

# Install dependencies

# Install curl
RUN apk add curl
# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

RUN source $HOME/.local/bin/env

WORKDIR /app

COPY pyproject.toml /app

ENTRYPOINT [ "bash" ]