# 定义版本号
$version = "1.0.0"

# 定义目标框架
$frameworks = @("net8.0-windows", "net6.0-windows")

# 定义发布配置
$configurations = @("Release")# @("Debug", "Release")

# 定义运行时
$runtimes = @("win-x64", "win-x86")

# 创建发布目录
$publishPath = ".\publish"
if (Test-Path $publishPath) {
    Remove-Item $publishPath -Recurse -Force
}
New-Item -ItemType Directory -Path $publishPath | Out-Null

# 遍历所有配置进行构建
foreach ($framework in $frameworks) {
    foreach ($configuration in $configurations) {
        foreach ($runtime in $runtimes) {
            Write-Host "Building for $framework - $configuration - $runtime" -ForegroundColor Green

            # 构建路径
            $buildPath = ".\bin\$configuration\$framework\$runtime"
            
            # 发布应用
            dotnet publish "TcpTransferSerialPortGui.csproj" `
                -c $configuration `
                -f $framework `
                -r $runtime `
                --self-contained true `
                /p:PublishSingleFile=true `
                /p:IncludeNativeLibrariesForSelfExtract=true

            # 创建ZIP文件名
            $zipName = "TcpTransferSerialPortGui-v$version-$framework-$configuration-$runtime.zip"
            $zipPath = Join-Path $publishPath $zipName

            # 压缩文件
            Write-Host "Creating zip: $zipName" -ForegroundColor Yellow
            Compress-Archive -Path "$buildPath\*" -DestinationPath $zipPath -Force
        }

        # 创建便携版（不包含运行时）
        Write-Host "Building portable version for $framework - $configuration" -ForegroundColor Green
        
        dotnet publish "TcpTransferSerialPortGui.csproj" `
            -c $configuration `
            -f $framework `
            --self-contained false

        # 压缩便携版
        $portableZipName = "TcpTransferSerialPortGui-v$version-$framework-$configuration-portable.zip"
        $portablePath = Join-Path $publishPath $portableZipName
        $portableBuildPath = ".\bin\$configuration\$framework\publish"
        
        Write-Host "Creating portable zip: $portableZipName" -ForegroundColor Yellow
        Compress-Archive -Path "$portableBuildPath\*" -DestinationPath $portablePath -Force
    }
}

Write-Host "`nBuild completed! Check the 'publish' folder for the output files." -ForegroundColor Green

# 列出生成的文件
Get-ChildItem $publishPath | ForEach-Object {
    Write-Host $_.Name -ForegroundColor Cyan
} 