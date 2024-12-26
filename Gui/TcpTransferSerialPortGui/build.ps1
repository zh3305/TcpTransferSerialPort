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

            # 构建路径 (注意这里改为 publish 子目录)
            $buildPath = ".\bin\$configuration\$framework\$runtime\publish"
            
            # 发布应用
            dotnet publish "TcpTransferSerialPortGui.csproj" `
                -c $configuration `
                -f $framework `
                -r $runtime `
                --self-contained true `
                /p:PublishSingleFile=true `
                /p:IncludeNativeLibrariesForSelfExtract=true

            # 创建ZIP文件名
            $zipName = "TcpTransferSerialPortGui-v$version-$framework-$runtime.zip"
            $zipPath = Join-Path $publishPath $zipName

            # 压缩文件
            Write-Host "Creating zip: $zipName" -ForegroundColor Yellow
            Compress-Archive -Path "$buildPath\*" -DestinationPath $zipPath -Force
        }

        # 创建依赖.NET运行时的版本
        Write-Host "Building framework-dependent version for $framework - $configuration" -ForegroundColor Green
        
        dotnet publish "TcpTransferSerialPortGui.csproj" `
            -c $configuration `
            -f $framework `
            --self-contained false `
            /p:PublishSingleFile=true `
            /p:IncludeNativeLibrariesForSelfExtract=true `
            /p:EnableCompressionInSingleFile=true

        # 压缩框架依赖版本
        $frameworkDependentZipName = "TcpTransferSerialPortGui-v$version-$framework-requires-runtime.zip"
        $frameworkDependentPath = Join-Path $publishPath $frameworkDependentZipName
        $frameworkDependentBuildPath = ".\bin\$configuration\$framework\publish"
        
        Write-Host "Creating framework-dependent zip: $frameworkDependentZipName" -ForegroundColor Yellow
        Compress-Archive -Path "$frameworkDependentBuildPath\*" -DestinationPath $frameworkDependentPath -Force
    }
}

Write-Host "`nBuild completed! Check the 'publish' folder for the output files." -ForegroundColor Green

# 列出生成的文件
Get-ChildItem $publishPath | ForEach-Object {
    Write-Host $_.Name -ForegroundColor Cyan
} 