ARG BUILD_FROM
FROM ${BUILD_FROM}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AIRNANNY_HOME=/opt/airnanny \
    AIRNANNY_STATE_DIR=/data/state

# musllinux aarch64 wheels exist for all three, so no toolchain is installed.
RUN pip install --no-cache-dir \
        "cryptography>=42" \
        "paho-mqtt==2.1.0" \
        "pyserial>=3.5"

# vendor/ mirrors the breeze_control layout exactly: the frozen firmware host
# code derives its pinned store paths from __file__, so the relative positions
# of host/ and firmware/ are load-bearing and must not be flattened.
COPY vendor/ /opt/airnanny/
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
