using System;
using System.IO;
using System.IO.Ports;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Concurrent;

namespace TcpTransferSerialPortGui
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SerialPort _serialPort;
        private TcpClient _tcpClient;
        private TcpListener _tcpListener;
        private UdpClient _udpClient;
        private bool _isRunning;
        private bool _isSerialPortOpen;
        private bool _isNetworkOpen;
        private CancellationTokenSource _cancellationTokenSource;
        private readonly ConcurrentDictionary<string, TcpClient> _connectedClients = new ConcurrentDictionary<string, TcpClient>();
        private bool _showHex = false;
        private const int MAX_LOG_LINES = 1000; // 最大日志行数
        private readonly object _logLock = new object(); // 日志同步锁

        public MainWindow()
        {
            InitializeComponent();
            InitializeControls();
        }

        private void InitializeControls()
        {
            // 初始化串口下拉框
            var portNames = SerialPort.GetPortNames();
            ComPortComboBox.ItemsSource = portNames;
            if (portNames.Length > 0)
            {
                ComPortComboBox.SelectedIndex = portNames.Length - 1; // 选择最后一个串口
            }
            
            // 初始化波特率下拉框
            BaudRateComboBox.ItemsSource = new[] { 9600, 19200, 38400, 57600, 115200 };
            BaudRateComboBox.SelectedValue = 115200; // 默认选择 115200

            // 设置默认值
            IpAddressTextBox.Text = "127.0.0.1"; // 客户端默认连接本地回环地址
            PortTextBox.Text = "8886";
            NetworkModeComboBox.SelectedIndex = 0;

            // 加载本地IP地址列表
            LoadLocalIpAddresses();

            // 设置初始可见性
            UpdateIpAddressVisibility();

            // 初始化按钮状态
            SerialPortButton.IsEnabled = true;
            NetworkButton.IsEnabled = false;
            StopButton.IsEnabled = false;
        }

        private void LoadLocalIpAddresses()
        {
            IpAddressComboBox.Items.Clear();
            
            // 添加本地回环地址
            IpAddressComboBox.Items.Add("127.0.0.1");
            
            // 添加所有本地IP地址
            var hostName = Dns.GetHostName();
            var ipAddresses = Dns.GetHostEntry(hostName).AddressList
                .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                .Select(ip => ip.ToString());

            foreach (var ip in ipAddresses)
            {
                IpAddressComboBox.Items.Add(ip);
            }

            // 添加 0.0.0.0 用于监听所有接口
            IpAddressComboBox.Items.Add("0.0.0.0");
        }

        private void NetworkModeComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            UpdateIpAddressVisibility();
        }

        private void UpdateIpAddressVisibility()
        {
            bool isServer = NetworkModeComboBox.SelectedIndex == 1 || NetworkModeComboBox.SelectedIndex == 3; // TCP服务器或UDP服务器
            
            // 更新控件可见性
            IpAddressComboBox.Visibility = isServer ? Visibility.Visible : Visibility.Collapsed;
            IpAddressTextBox.Visibility = isServer ? Visibility.Collapsed : Visibility.Visible;

            if (isServer)
            {
                // 确保ComboBox是可用的
                IpAddressComboBox.IsEnabled = true;
                if (IpAddressComboBox.Items.Count > 0)
                {
                    IpAddressComboBox.SelectedIndex = 0; // 默认选择第一项 (127.0.0.1)
                }
            }
            else
            {
                // 客户端模式下，如果IP地址为空，设置默认值
                if (string.IsNullOrWhiteSpace(IpAddressTextBox.Text))
                {
                    IpAddressTextBox.Text = "127.0.0.1";
                }
            }
        }

        private async void SerialPortButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!_isSerialPortOpen)
                {
                    // 打开串口
                    if (ComPortComboBox.SelectedItem == null)
                    {
                        MessageBox.Show("请选择串口", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    if (BaudRateComboBox.SelectedItem == null)
                    {
                        MessageBox.Show("请选择波特率", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    _serialPort = new SerialPort(
                        ComPortComboBox.SelectedItem.ToString(),
                        Convert.ToInt32(BaudRateComboBox.SelectedItem),
                        Parity.None, 8, StopBits.One);
                    _serialPort.Open();
                    
                    _isSerialPortOpen = true;
                    SerialPortButton.Content = "关闭串口";
                    NetworkButton.IsEnabled = true;
                    
                    // 禁用串口设置控件
                    ComPortComboBox.IsEnabled = false;
                    BaudRateComboBox.IsEnabled = false;
                    
                    LogMessage("串口已打开");
                }
                else
                {
                    // 关闭串口
                    await CloseSerialPort();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"串口操作错误: {ex.Message}");
                await CloseSerialPort();
            }
        }

        private async void NetworkButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!_isNetworkOpen)
                {
                    if (!_isSerialPortOpen)
                    {
                        MessageBox.Show("请先打开串口", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    // 验证网络参数
                    string selectedIp;
                    if (NetworkModeComboBox.SelectedIndex == 1 || NetworkModeComboBox.SelectedIndex == 3) // 服务器模式
                    {
                        selectedIp = IpAddressComboBox.SelectedItem?.ToString();
                        if (string.IsNullOrWhiteSpace(selectedIp))
                        {
                            MessageBox.Show("请选择服务器IP地址", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                    else // 客户端模式
                    {
                        selectedIp = IpAddressTextBox.Text;
                        if (string.IsNullOrWhiteSpace(selectedIp))
                        {
                            MessageBox.Show("请输入服务器IP地址", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }

                    if (!IPAddress.TryParse(selectedIp, out _))
                    {
                        MessageBox.Show("请输入有效的IP地址", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    if (string.IsNullOrWhiteSpace(PortTextBox.Text) || !int.TryParse(PortTextBox.Text, out int port) || port <= 0 || port > 65535)
                    {
                        MessageBox.Show("请输入有效的端口号（1-65535）", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    // 禁用网络设置控件
                    NetworkModeComboBox.IsEnabled = false;
                    IpAddressComboBox.IsEnabled = false;
                    IpAddressTextBox.IsEnabled = false;
                    PortTextBox.IsEnabled = false;

                    _cancellationTokenSource = new CancellationTokenSource();
                    _isNetworkOpen = true;
                    NetworkButton.Content = "关闭网络";
                    StopButton.IsEnabled = true;

                    // 根据选择的模式启动对应的网络服务
                    switch (NetworkModeComboBox.SelectedIndex)
                    {
                        case 0: // TCP客户端
                            await StartTcpClientMode();
                            break;
                        case 1: // TCP服务器
                            await StartTcpServerMode();
                            break;
                        case 2: // UDP客户端
                            await StartUdpMode();
                            break;
                        case 3: // UDP服务器
                            await StartUdpMode();
                            break;
                    }
                }
                else
                {
                    // 关闭网络连接
                    await CloseNetwork();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"网络操作错误: {ex.Message}");
                await CloseNetwork();
            }
        }

        private async Task CloseSerialPort()
        {
            if (_serialPort?.IsOpen == true)
            {
                try
                {
                    _serialPort.Close();
                    _serialPort.Dispose();
                    _serialPort = null;
                }
                catch (Exception ex)
                {
                    LogMessage($"关闭串口时出错: {ex.Message}");
                }
            }

            _isSerialPortOpen = false;
            SerialPortButton.Content = "打开串口";
            NetworkButton.IsEnabled = false;
            
            // 启用串口设置控件
            ComPortComboBox.IsEnabled = true;
            BaudRateComboBox.IsEnabled = true;

            LogMessage("串口已关闭");
        }

        private async Task CloseNetwork()
        {
            try
            {
                if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
                {
                    _cancellationTokenSource.Cancel();
                    await Task.Delay(100);
                }

                // 清理所有客户端连接
                foreach (var client in _connectedClients)
                {
                    await CleanupClientConnection(client.Key);
                }
                _connectedClients.Clear();

                if (_tcpListener != null)
                {
                    try
                    {
                        _tcpListener.Stop();
                        _tcpListener = null;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"关闭TCP监听器时出错: {ex.Message}");
                    }
                }

                if (_udpClient != null)
                {
                    try
                    {
                        _udpClient.Close();
                        _udpClient = null;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"关闭UDP连接时出错: {ex.Message}");
                    }
                }

                _isNetworkOpen = false;
                
                await Dispatcher.InvokeAsync(() => {
                    NetworkModeComboBox.IsEnabled = true;
                    IpAddressTextBox.IsEnabled = true;
                    IpAddressComboBox.IsEnabled = true;
                    PortTextBox.IsEnabled = true;
                    NetworkButton.Content = "开始网络";
                    StopButton.IsEnabled = false;
                });

                LogMessage("网络连接已关闭");
            }
            catch (Exception ex)
            {
                LogMessage($"关闭网络连接时出错: {ex.Message}");
            }
            finally
            {
                if (_cancellationTokenSource != null)
                {
                    _cancellationTokenSource.Dispose();
                    _cancellationTokenSource = null;
                }
            }
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await CloseNetwork();
            await CloseSerialPort();
        }

        private async Task StartTcpClientMode()
        {
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(IpAddressTextBox.Text, int.Parse(PortTextBox.Text));
            LogMessage("TCP客户端已连接");

            var stream = _tcpClient.GetStream();
            _ = CopyStreamAsync(_serialPort.BaseStream, stream, "串口->TCP", _cancellationTokenSource.Token);
            _ = CopyStreamAsync(stream, _serialPort.BaseStream, "TCP->串口", _cancellationTokenSource.Token);
        }

        private async Task StartTcpServerMode()
        {
            try
            {
                string selectedIp = IpAddressComboBox.SelectedItem.ToString();
                _tcpListener = new TcpListener(IPAddress.Parse(selectedIp), int.Parse(PortTextBox.Text));
                _tcpListener.Start();
                LogMessage("TCP服务器已启动");

                while (!_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    try
                    {
                        var client = await _tcpListener.AcceptTcpClientAsync(_cancellationTokenSource.Token);
                        string clientEndPoint = ((IPEndPoint)client.Client.RemoteEndPoint).ToString();
                        _connectedClients.TryAdd(clientEndPoint, client);
                        LogMessage($"客户端已连接: {clientEndPoint}");

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                using var clientStream = client.GetStream();
                                
                                var serialToTcpTask = Task.Run(async () =>
                                {
                                    byte[] buffer = new byte[4096];
                                    try
                                    {
                                        while (!_cancellationTokenSource.Token.IsCancellationRequested)
                                        {
                                            try
                                            {
                                                var readTask = _serialPort.BaseStream.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                                                int bytesRead = await readTask;
                                                
                                                if (bytesRead > 0)
                                                {
                                                    await clientStream.WriteAsync(buffer.AsMemory(0, bytesRead), _cancellationTokenSource.Token);
                                                    var data = new byte[bytesRead];
                                                    Array.Copy(buffer, 0, data, 0, bytesRead);
                                                    string hexString = _showHex ? $"\nHEX: {BitConverter.ToString(data)}" : "";
                                                    LogMessage($"串口->TCP({clientEndPoint}): 传输 {bytesRead} 字节{hexString}");
                                                }
                                            }
                                            catch (OperationCanceledException)
                                            {
                                                throw;
                                            }
                                            catch (IOException)
                                            {
                                                // 如果发生IO错误，等待一段时间后继续
                                                await Task.Delay(100, _cancellationTokenSource.Token);
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        LogMessage($"串口->TCP({clientEndPoint}): 传输已取消");
                                    }
                                    catch (Exception ex)
                                    {
                                        LogMessage($"串口->TCP({clientEndPoint}) 错误: {ex.Message}");
                                        LogMessage($"异常类型: {ex.GetType().Name}");
                                        LogMessage($"堆栈跟踪: {ex.StackTrace}");
                                    }
                                }, _cancellationTokenSource.Token);

                                var tcpToSerialTask = Task.Run(async () =>
                                {
                                    byte[] buffer = new byte[4096];
                                    try
                                    {
                                        while (!_cancellationTokenSource.Token.IsCancellationRequested)
                                        {
                                            try
                                            {
                                                int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length, _cancellationTokenSource.Token);
                                                if (bytesRead == 0)
                                                {
                                                    LogMessage($"TCP({clientEndPoint})->串口: 连接已关闭");
                                                    break;
                                                }
                                                if (bytesRead > 0)
                                                {
                                                    await _serialPort.BaseStream.WriteAsync(buffer.AsMemory(0, bytesRead), _cancellationTokenSource.Token);
                                                    var data = new byte[bytesRead];
                                                    Array.Copy(buffer, 0, data, 0, bytesRead);
                                                    string hexString = _showHex ? $"\nHEX: {BitConverter.ToString(data)}" : "";
                                                    LogMessage($"TCP({clientEndPoint})->串口: 传输 {bytesRead} 字节{hexString}");
                                                }
                                            }
                                            catch (OperationCanceledException)
                                            {
                                                throw;
                                            }
                                            catch (IOException)
                                            {
                                                // 如果发生IO错误，等待一段时间后继续
                                                await Task.Delay(100, _cancellationTokenSource.Token);
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        LogMessage($"TCP({clientEndPoint})->串口: 传输已取消");
                                    }
                                    catch (Exception ex)
                                    {
                                        LogMessage($"TCP({clientEndPoint})->串口 错误: {ex.Message}");
                                        LogMessage($"异常类型: {ex.GetType().Name}");
                                        LogMessage($"堆栈跟踪: {ex.StackTrace}");
                                    }
                                }, _cancellationTokenSource.Token);

                                await Task.WhenAll(serialToTcpTask, tcpToSerialTask);
                            }
                            catch (Exception ex)
                            {
                                LogMessage($"客户端 {clientEndPoint} 处理错误: {ex.Message}");
                                LogMessage($"异常类型: {ex.GetType().Name}");
                                LogMessage($"堆栈跟踪: {ex.StackTrace}");
                            }
                            finally
                            {
                                await CleanupClientConnection(clientEndPoint);
                            }
                        }, _cancellationTokenSource.Token);
                    }
                    catch (OperationCanceledException) when (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"接受客户端连接时出错: {ex.Message}");
                        await Task.Delay(1000, _cancellationTokenSource.Token);
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"TCP服务器错误: {ex.Message}");
                throw;
            }
        }

        private async Task CleanupClientConnection(string clientEndPoint)
        {
            if (_connectedClients.TryRemove(clientEndPoint, out var client))
            {
                try
                {
                    client.Close();
                    client.Dispose();
                    LogMessage($"客户端断开连接: {clientEndPoint}");
                }
                catch (Exception ex)
                {
                    LogMessage($"关闭客户端连接时出错 {clientEndPoint}: {ex.Message}");
                }
            }
        }

        private async Task StartUdpMode()
        {
            int port = int.Parse(PortTextBox.Text);
            string ipAddress = IpAddressTextBox.Text;

            if (NetworkModeComboBox.SelectedIndex == 2) // UDP客户端
            {
                _udpClient = new UdpClient();
                await Task.Run(() => _udpClient.Connect(ipAddress, port));
                LogMessage("UDP客户端已启动");
            }
            else // UDP服务器
            {
                _udpClient = new UdpClient(new IPEndPoint(IPAddress.Parse(IpAddressComboBox.SelectedItem.ToString()), port));
                LogMessage("UDP服务器已启动");
            }

            // 启动UDP数据处理
            _ = ProcessUdpDataAsync(_cancellationTokenSource.Token);
        }

        private async Task ProcessUdpDataAsync(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    // 接收UDP数据
                    UdpReceiveResult result = await _udpClient.ReceiveAsync();
                    await _serialPort.BaseStream.WriteAsync(result.Buffer, 0, result.Buffer.Length, token);
                    LogMessage($"UDP->串口: 传输 {result.Buffer.Length} 字节");

                    // 从串口读取数据并通过UDP发送
                    byte[] buffer = new byte[4096];
                    int bytesRead = await _serialPort.BaseStream.ReadAsync(buffer, 0, buffer.Length, token);
                    if (bytesRead > 0)
                    {
                        if (NetworkModeComboBox.SelectedIndex == 2) // UDP客户端
                        {
                            await _udpClient.SendAsync(buffer, bytesRead);
                        }
                        else // UDP服务器
                        {
                            await _udpClient.SendAsync(buffer, bytesRead, result.RemoteEndPoint);
                        }
                        LogMessage($"串口->UDP: 传输 {bytesRead} 字节");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                LogMessage("UDP传输已停止");
            }
            catch (Exception ex)
            {
                LogMessage($"UDP错误: {ex.Message}");
            }
        }

        private async Task CopyStreamAsync(Stream source, Stream destination, string direction, CancellationToken token)
        {
            byte[] buffer = new byte[4096];
            
            try
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        // 检查串口状态
                        if (source.GetType().Name == "SerialPortStream" && !_serialPort.IsOpen)
                        {
                            LogMessage($"{direction}: 串口已关闭");
                            break;
                        }

                        int bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, token);
                        
                        if (bytesRead == 0)
                        {
                            // 读取到0字节，可能是连接正常关闭
                            LogMessage($"{direction}: 连接已正常关闭");
                            break;
                        }

                        // 检查目标串口状态
                        if (destination.GetType().Name == "SerialPortStream" && !_serialPort.IsOpen)
                        {
                            LogMessage($"{direction}: 目标串口已关闭");
                            break;
                        }

                        await destination.WriteAsync(buffer, 0, bytesRead, token);
                        LogMessage($"{direction}: 传输 {bytesRead} 字节");
                    }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        LogMessage($"{direction}: 传输已正常停止");
                        break;
                    }
                    catch (IOException ex)
                    {
                        if (token.IsCancellationRequested)
                        {
                            break;
                        }
                        LogMessage($"{direction}: IO错误: {ex.Message}");
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        LogMessage($"{direction}: 连接已关闭");
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (token.IsCancellationRequested)
                        {
                            break;
                        }
                        LogMessage($"{direction}: 发生错误: {ex.Message}");
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"{direction} 发生未处理错误: {ex.Message}");
            }
            finally
            {
                // 如果不是因为取消而退出，则清理连接
                if (!token.IsCancellationRequested)
                {
                    var clientEndPoint = direction.Contains("TCP(") ? 
                        direction.Split('(', ')')[1] : null;
                    
                    if (clientEndPoint != null)
                    {
                        await CleanupClientConnection(clientEndPoint);
                    }
                }
            }
        }

        private async Task CloseNetworkOnly()
        {
            try
            {
                // 关闭TCP连接
                if (_tcpClient != null)
                {
                    try
                    {
                        _tcpClient.Close();
                        _tcpClient.Dispose();
                        _tcpClient = null;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"关闭TCP客户端时出错: {ex.Message}");
                    }
                }

                if (_tcpListener != null)
                {
                    try
                    {
                        _tcpListener.Stop();
                        _tcpListener = null;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"关闭TCP监听器时出错: {ex.Message}");
                    }
                }

                // 关闭UDP连接
                if (_udpClient != null)
                {
                    try
                    {
                        _udpClient.Close();
                        _udpClient = null;
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"关闭UDP连接时出错: {ex.Message}");
                    }
                }

                _isNetworkOpen = false;
                
                // 启用网络相关控件
                await Dispatcher.InvokeAsync(() => {
                    NetworkModeComboBox.IsEnabled = true;
                    IpAddressTextBox.IsEnabled = true;
                    IpAddressComboBox.IsEnabled = true;
                    PortTextBox.IsEnabled = true;
                    NetworkButton.Content = "开始网络";
                    StopButton.IsEnabled = false;
                });

                LogMessage("网络连接已关闭");
            }
            catch (Exception ex)
            {
                LogMessage($"关闭网络连接时出错: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            Dispatcher.Invoke(() =>
            {
                lock (_logLock)
                {
                    // 添加新日志
                    LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");

                    // 检查日志行数
                    var lineCount = LogTextBox.LineCount;
                    if (lineCount > MAX_LOG_LINES)
                    {
                        // 计算需要删除的行数
                        int linesToRemove = lineCount - MAX_LOG_LINES;
                        
                        // 获取文本
                        var text = LogTextBox.Text;
                        
                        // 找到要保留的文本的起始位置
                        int pos = 0;
                        for (int i = 0; i < linesToRemove; i++)
                        {
                            pos = text.IndexOf('\n', pos) + 1;
                            if (pos == 0) break;
                        }
                        
                        // 删除旧日志
                        LogTextBox.Text = text[pos..];
                    }

                    // 滚动到底部
                    LogTextBox.ScrollToEnd();
                }
            });
        }

        protected override async void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            try
            {
                await CloseNetwork();
                await CloseSerialPort();
            }
            catch (Exception ex)
            {
                LogMessage($"关闭应用程序时出错: {ex.Message}");
            }
            finally
            {
                base.OnClosing(e);
            }
        }

        // 加新方法来控制配置控件的启用状态
        private void SetConfigControlsEnabled(bool enabled)
        {
            ComPortComboBox.IsEnabled = enabled;
            BaudRateComboBox.IsEnabled = enabled;
            NetworkModeComboBox.IsEnabled = enabled;
            IpAddressTextBox.IsEnabled = enabled;
            PortTextBox.IsEnabled = enabled;
        }

        private void ShowHexCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            _showHex = ShowHexCheckBox.IsChecked ?? false;
        }
    }
}