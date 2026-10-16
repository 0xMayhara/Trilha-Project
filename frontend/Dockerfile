# syntax=docker/dockerfile:1
# Base images are pinned by digest (SPEC-0001 SEC-17); Dependabot proposes updates.
FROM docker.io/library/node:25-trixie-slim@sha256:aabbe39553d15ede8a97cc60c9e1a97034ff772afcf696ea42b94e7f5f2ec71b AS deps
RUN npm install --global --ignore-scripts pnpm@12.14.0
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY . .
RUN pnpm build

FROM docker.io/library/node:25-trixie-slim@sha256:aabbe39553d15ede8a97cc60c9e1a97034ff772afcf696ea42b94e7f5f2ec71b AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
# The server only needs node. The package managers shipped with the base image are unused attack
# surface, and their bundled dependencies carry vulnerabilities that this project cannot patch.
RUN rm -rf /usr/local/lib/node_modules /opt/yarn-v* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
# Code stays owned by root: the runtime user can read but not modify it.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
USER node
EXPOSE 3000
CMD ["node", "server.js"]
