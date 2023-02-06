# docker build -t l7mp/direct-one2one-call-server .
# docker push l7mp/direct-one2one-call-server

FROM node:16-alpine3.15

RUN apk update && \
    apk upgrade && \
    apk add --no-cache git

# Create app directory
WORKDIR /app

# Bundle app source
COPY *.js ./
COPY static/ ./static/
COPY package.json ./

# SSL keys will come from a Kubernetes secret
# Uncomment the above if you want the container to package the keys instead
#COPY keys/* ./keys/

# RUN npm install --loglevel verbose --unsafe-perm
RUN npm install --unsafe-perm

# Expose the control port
EXPOSE 8888

# test container
# CMD exec /bin/sh -c "trap : TERM INT; (while true; do sleep 1000; done) & wait"

CMD [ "npm", "start" ]
