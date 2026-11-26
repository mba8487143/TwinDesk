# TwinDesk Relay in a container (the other way: relay/deploy/install.sh with systemd).
#   docker build -t twindesk-relay -f relay/deploy/Dockerfile relay
#   docker run -d --name twindesk-relay --restart unless-stopped -p 47100:47100 \
#     -e RELAY_KEY="$(openssl rand -hex 24)" twindesk-relay
# (docker logs twindesk-relay shows the start line; keep the key you gave it.)
FROM node:22-alpine
WORKDIR /app
COPY twindesk-relay.js ./
ENV RELAY_PORT=47100 RELAY_HOST=0.0.0.0
EXPOSE 47100
USER node
CMD ["node", "twindesk-relay.js"]
