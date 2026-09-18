#!/bin/bash
# ============================================================================
# 卡密授权测试客户端 - 构建脚本
# ============================================================================
# 【为什么需要这个脚本】
# 本机 Git Bash 中 APPDATA / USERPROFILE / ProgramFiles 等 Windows 环境变量
# 缺失或为 POSIX 风格路径，导致 .NET SDK 的
# NuGet.Configuration.ConfigurationDefaults 静态构造失败，报：
#     error : Value cannot be null. (Parameter 'path1')
# 解决：用 `env -i` 提供完整的纯 Windows 风格环境变量后再调用 dotnet。
#
# 【用法】
#   bash server/license-test-client/build.sh            # 构建 Debug
#   bash server/license-test-client/build.sh run        # 构建并启动
#   bash server/license-test-client/build.sh publish    # 发布单文件 exe
#   bash server/license-test-client/build.sh clean      # 清理
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSPROJ="$SCRIPT_DIR/LicenseTester.csproj"

WIN_ENV=(
  SystemRoot='C:\Windows'
  windir='C:\Windows'
  PATH='C:\Program Files\dotnet;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem'
  APPDATA='C:\Users\XIaoL\AppData\Roaming'
  LOCALAPPDATA='C:\Users\XIaoL\AppData\Local'
  USERPROFILE='C:\Users\XIaoL'
  HOMEDRIVE='C:'
  HOMEPATH='\Users\XIaoL'
  TEMP='C:\Users\XIaoL\AppData\Local\Temp'
  TMP='C:\Users\XIaoL\AppData\Local\Temp'
  ProgramData='C:\ProgramData'
  'ProgramFiles=C:\Program Files'
  'ProgramFiles(x86)=C:\Program Files (x86)'
  NUMBER_OF_PROCESSORS=8
  PROCESSOR_ARCHITECTURE=AMD64
  DOTNET_CLI_TELEMETRY_OPTOUT=1
  DOTNET_NOLOGO=1
  DOTNET_CLI_UI_LANGUAGE=zh-CN
)

DOTNET='C:\Program Files\dotnet\dotnet.exe'

run_dotnet() {
  env -i "${WIN_ENV[@]}" "$DOTNET" "$@"
}

OUT_EXE="$SCRIPT_DIR/bin/Debug/net10.0-windows/LicenseTester.exe"

case "${1:-build}" in
  run)
    echo ">>> 构建并启动"
    run_dotnet build "$CSPROJ" -c Debug --nologo
    echo ">>> 启动 $OUT_EXE"
    "$OUT_EXE" &
    ;;
  publish)
    echo ">>> 发布单文件 exe (win-x64, self-contained=false)"
    run_dotnet publish "$CSPROJ" -c Release -r win-x64 --self-contained false \
      -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
      -o "$SCRIPT_DIR/dist" --nologo
    echo ">>> 产物: $SCRIPT_DIR/dist"
    ;;
  clean)
    echo ">>> 清理"
    run_dotnet clean "$CSPROJ" -c Debug --nologo || true
    run_dotnet clean "$CSPROJ" -c Release --nologo || true
    ;;
  *)
    echo ">>> dotnet build"
    run_dotnet build "$CSPROJ" -c Debug --nologo "$@"
    ;;
esac

echo ">>> 完成"
