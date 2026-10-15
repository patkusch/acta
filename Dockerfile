FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY bin ./bin
COPY src ./src
USER node
ENV PORT=8080
EXPOSE 8080
CMD ["node", "bin/acta.mjs", "serve"]
