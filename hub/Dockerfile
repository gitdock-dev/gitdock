FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3848
ENV NODE_ENV=production
CMD ["node", "server.js"]
