#!/bin/bash
docker buildx build --platform linux/arm64 --tag timothyjmiller/cloudflare-ddns:latest --load ../
