# Dockerfile (自动获取项目名)
# 这个版本会自动从 Cargo.toml 读取项目名，并使用 Clang 作为 C 编译器以解决兼容性问题。
# 它可以通过 BUILD_PROFILE 参数来构建 release 或 debug 版本。

# ---- 阶段 1: 构建器 (Builder) ----
# 使用官方的 rust:alpine 镜像作为构建环境，并命名为 "builder" 阶段
FROM rust:alpine AS builder

# 1. 定义构建参数
#    允许用户在构建时指定 'release' 或 'debug'
#    默认值为 'release'
ARG BUILD_PROFILE=release

# 2. 安装构建所需的系统依赖
#    我们使用 clang 和 lld (LLVM's linker) 来代替 gcc，以获得更好的兼容性。
RUN apk add --no-cache clang lld musl-dev

# 3. 为 Rust 工具链添加 musl 编译目标
RUN rustup target add x86_64-unknown-linux-musl

# 4. 为 musl 目标设置 C 编译器和 Linker 环境变量
#    这是最关键的一步，它强制 cargo 和 cc-rs 使用 clang 来编译和链接。
ENV CC_x86_64_unknown_linux_musl=clang
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang

# 5. 设置容器内的工作目录
WORKDIR /usr/src/app

# 6. 复制您的整个项目到容器的工作目录中
#    这个命令会把 Dockerfile 所在目录的所有文件（包括 src, Cargo.toml 等）都复制进去
COPY . .

# 7. 根据构建参数编译项目
#    - 根据 BUILD_PROFILE 设置 cargo 的编译标志
#    - 编译项目
#    - 将编译产物移动并重命名为一个固定的名称 `./app`
RUN \
    # 设置 cargo 编译标志
    if [ "$BUILD_PROFILE" = "release" ]; then \
        CARGO_FLAGS="--release"; \
    else \
        CARGO_FLAGS=""; \
    fi && \
    \
    # 从 Cargo.toml 提取项目名
    PROJECT_NAME=$(grep '^name' Cargo.toml | head -n 1 | sed -e 's/name = "//' -e 's/"//') && \
    \
    # 编译项目
    cargo build --target x86_64-unknown-linux-musl $CARGO_FLAGS && \
    \
    # 移动并重命名产物
    mv "target/x86_64-unknown-linux-musl/$BUILD_PROFILE/$PROJECT_NAME" ./app


# ---- 阶段 2: 最终镜像 (Final Image) ----
# 使用一个非常小的 alpine 镜像作为最终的运行环境，以减小镜像体积
FROM alpine:latest

# 设置工作目录
WORKDIR /root/

# 1. 从 "builder" 阶段复制编译好的、已重命名的二进制文件
COPY --from=builder /usr/src/app/app .

# 2. 设置容器启动时要执行的默认命令
CMD ["./app"]
