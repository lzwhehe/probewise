FROM python:3.12-slim
WORKDIR /app
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=$PIP_INDEX_URL PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1
COPY pyproject.toml README.md ./
COPY probewise ./probewise
RUN pip install .
COPY web ./web
# 预先算好基准测试结果，页面打开即可查看
RUN probewise bench --json /app/bench.json > /dev/null
ENV PROBEWISE_WEB=/app/web PROBEWISE_DB=/data/probewise.db PROBEWISE_BENCH_FILE=/app/bench.json
RUN mkdir -p /data && useradd -r -u 10001 probewise && chown probewise /data
USER probewise
VOLUME /data
EXPOSE 8000
CMD ["uvicorn", "probewise.api:app", "--host", "0.0.0.0", "--port", "8000"]
