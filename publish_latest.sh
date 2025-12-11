#!/usr/bin/env bash
set -euo pipefail

VERSION=$(TZ=Asia/Shanghai date +%Y%m%d%H%M)
IMAGE="24802117/arouter:latest"
IMAGE2="24802117/arouter:${VERSION}"

# Build front-end if available
if [ -d "web" ]; then
  (cd web && npm install && npm run build)
fi

docker build --build-arg BUILD_VERSION="${VERSION}" -t "$IMAGE" -t "$IMAGE2" .
docker push "$IMAGE"
echo "Published $IMAGE"

docker push "$IMAGE2"
echo "Published $IMAGE2"

echo "Version tag used: ${VERSION}"
