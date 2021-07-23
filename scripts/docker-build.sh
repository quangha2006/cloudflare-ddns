#!/bin/bash
docker buildx build --platform linux/arm64 --tag quangha2006/cloudflare-ddns:latest --load ../
