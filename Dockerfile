FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
# Mount a persistent volume at /data (Fly volume, Railway volume, Render disk, docker -v ...)
ENV OVU_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "index.js"]
