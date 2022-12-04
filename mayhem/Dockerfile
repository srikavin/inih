# Build Stage
FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y clang

ADD . /inih
WORKDIR /inih

WORKDIR mayhem

RUN clang -g -fsanitize=fuzzer,address,undefined string_driver.c ../ini.c -o inihfuzz_string

# Package Stage
FROM --platform=linux/amd64 ubuntu:20.04

COPY --from=builder /inih/mayhem/inihfuzz_string /
