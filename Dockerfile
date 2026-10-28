FROM docker.io/library/python:3.12-slim

# Reported by /health so "which build is running?" can be answered from any machine.
# Pass at build time: docker build --build-arg HOYOLAB_MCP_VERSION=1.2.3 .
ARG HOYOLAB_MCP_VERSION=dev

# Pinned to match Open WebUI's own MCP SDK version (backend/requirements.txt: mcp==1.27.2)
# so client and server speak the same protocol revision and the FastMCP API surface.
RUN pip install --no-cache-dir \
        'mcp==1.27.2' \
        'httpx==0.28.1' \
        'PyJWT==2.10.1' \
        'cryptography==44.0.0'

WORKDIR /app
COPY hoyolab_mcp/ /app/hoyolab_mcp/

# Non-root: this process handles other people's login cookies, so it should not run
# with any more privilege than it needs.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin hoyolab \
 && mkdir -p /data \
 && chown -R hoyolab:hoyolab /app /data
USER hoyolab

ENV HOYOLAB_MCP_HOST=0.0.0.0 \
    HOYOLAB_MCP_PORT=8899 \
    HOYOLAB_MCP_DB=/data/hoyolab.db \
    HOYOLAB_MCP_VERSION=${HOYOLAB_MCP_VERSION} \
    PYTHONUNBUFFERED=1

EXPOSE 8899

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8899/health',timeout=4).status==200 else 1)"

CMD ["python", "-m", "hoyolab_mcp.main"]
