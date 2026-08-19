FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
USER root
EXPOSE 22
CMD ["node", "index.js"]
