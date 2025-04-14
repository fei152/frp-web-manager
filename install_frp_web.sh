#!/bin/bash

# 一键部署 frp Web 界面脚本，类似宝塔面板
FRP_VERSION="0.61.0"
FRP_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz"
INSTALL_DIR="/usr/local/frp"
CONFIG_DIR="/etc/frp"
WEB_DIR="/opt/frp_web"
PYTHON_PORT=5000

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 检查命令
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# 安装依赖
install_dependencies() {
    echo "检查并安装依赖..."
    if [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt install -y python3 python3-pip wget tar
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y python3 python3-pip wget tar
    else
        echo -e "${RED}不支持的系统，请手动安装 python3、pip3、wget、tar！${NC}"
        exit 1
    fi
}

# 安装 frp
install_frp() {
    echo "正在下载 frp v${FRP_VERSION}..."
    wget -q "$FRP_URL" -O frp.tar.gz
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}下载失败，请检查网络！${NC}"
        exit 1
    fi

    tar -xzf frp.tar.gz
    mkdir -p "$INSTALL_DIR"
    mv frp_${FRP_VERSION}_linux_amd64/frp* "$INSTALL_DIR/"
    rm -rf frp.tar.gz frp_${FRP_VERSION}_linux_amd64
}

# 安装 Flask
install_flask() {
    echo "安装 Flask..."
    pip3 install flask
}

# 创建 Web 界面代码
create_web_files() {
    echo "创建 Web 界面文件..."
    mkdir -p "$WEB_DIR/templates"

    # 创建 frp_web.py
    cat > "$WEB_DIR/frp_web.py" <<'EOF'
from flask import Flask, render_template, request, redirect, flash, url_for
import configparser
import os
import subprocess
import random
import string

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# 配置路径
CONFIG_DIR = "/etc/frp"
FRPS_CONFIG = os.path.join(CONFIG_DIR, "frps.ini")
FRPC_CONFIG = os.path.join(CONFIG_DIR, "frpc.ini")
INSTALL_DIR = "/usr/local/frp"

def get_service_status(service):
    try:
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
        return result.stdout.strip() == "active"
    except:
        return False

def restart_service(service):
    subprocess.run(["systemctl", "restart", service], capture_output=True)

@app.route('/')
def index():
    frps_status = get_service_status("frps")
    frpc_status = get_service_status("frpc")
    return render_template('index.html', frps_status=frps_status, frpc_status=frpc_status)

@app.route('/config_frps', methods=['GET', 'POST'])
def config_frps():
    if request.method == 'POST':
        bind_port = request.form.get('bind_port', '7000')
        token = request.form.get('token') or ''.join(random.choices(string.hexdigits.lower(), k=16))
        enable_http = request.form.get('enable_http') == 'on'
        vhost_http_port = request.form.get('vhost_http_port', '80') if enable_http else ''
        vhost_https_port = request.form.get('vhost_https_port', '443') if enable_http else ''
        subdomain_host = request.form.get('subdomain_host', '') if enable_http else ''

        config = configparser.ConfigParser()
        config['common'] = {
            'bind_port': bind_port,
            'token': token
        }
        if enable_http:
            config['common']['vhost_http_port'] = vhost_http_port
            config['common']['vhost_https_port'] = vhost_https_port
            if subdomain_host:
                config['common']['subdomain_host'] = subdomain_host

        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FRPS_CONFIG, 'w') as f:
            config.write(f)

        restart_service("frps")
        flash('服务端配置已保存并重启！', 'success')
        return redirect(url_for('index'))

    config = configparser.ConfigParser()
    if os.path.exists(FRPS_CONFIG):
        config.read(FRPS_CONFIG)
    return render_template('config_frps.html', config=config)

@app.route('/config_frpc', methods=['GET', 'POST'])
def config_frpc():
    if request.method == 'POST':
        server_addr = request.form.get('server_addr')
        server_port = request.form.get('server_port', '7000')
        token = request.form.get('token')
        enable_http = request.form.get('enable_http') == 'on'
        service_name = request.form.get('service_name', 'web')
        local_ip = request.form.get('local_ip', '127.0.0.1')
        local_port = request.form.get('local_port')
        remote_port = request.form.get('remote_port', '') if not enable_http else ''
        proxy_type = request.form.get('proxy_type', 'http') if enable_http else 'tcp'
        custom_domains = request.form.get('custom_domains', '') if enable_http else ''
        subdomain = request.form.get('subdomain', '') if enable_http else ''

        config = configparser.ConfigParser()
        config['common'] = {
            'server_addr': server_addr,
            'server_port': server_port,
            'token': token
        }
        config[service_name] = {
            'type': proxy_type,
            'local_ip': local_ip,
            'local_port': local_port
        }
        if enable_http and custom_domains:
            config[service_name]['custom_domains'] = custom_domains
        if enable_http and subdomain:
            config[service_name]['subdomain'] = subdomain
        if not enable_http and remote_port:
            config[service_name]['remote_port'] = remote_port

        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FRPC_CONFIG, 'w') as f:
            config.write(f)

        restart_service("frpc")
        flash('客户端配置已保存并重启！', 'success')
        return redirect(url_for('index'))

    config = configparser.ConfigParser()
    if os.path.exists(FRPC_CONFIG):
        config.read(FRPC_CONFIG)
    return render_template('config_frpc.html', config=config)

@app.route('/service/<action>/<service>')
def service_action(action, service):
    if action in ['start', 'stop', 'restart']:
        subprocess.run([f"systemctl {action} {service}"], shell=True, capture_output=True)
        flash(f"{service} 已{action}！", 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

    # 创建 index.html
    cat > "$WEB_DIR/templates/index.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>FRP Web 管理</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="mb-4">FRP Web 管理</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'success' if category == 'success' else 'danger' }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div class="row">
            <div class="col-md-6">
                <h3>服务端 (frps)</h3>
                <p>状态: {{ '运行中' if frps_status else '已停止' }}</p>
                <a href="{{ url_for('config_frps') }}" class="btn btn-primary">配置服务端</a>
                <div class="mt-2">
                    <a href="{{ url_for('service_action', action='start', service='frps') }}" class="btn btn-success">启动</a>
                    <a href="{{ url_for('service_action', action='stop', service='frps') }}" class="btn btn-warning">停止</a>
                    <a href="{{ url_for('service_action', action='restart', service='frps') }}" class="btn btn-info">重启</a>
                </div>
            </div>
            <div class="col-md-6">
                <h3>客户端 (frpc)</h3>
                <p>状态: {{ '运行中' if frpc_status else '已停止' }}</p>
                <a href="{{ url_for('config_frpc') }}" class="btn btn-primary">配置客户端</a>
                <div class="mt-2">
                    <a href="{{ url_for('service_action', action='start', service='frpc') }}" class="btn btn-success">启动</a>
                    <a href="{{ url_for('service_action', action='stop', service='frpc') }}" class="btn btn-warning">停止</a>
                    <a href="{{ url_for('service_action', action='restart', service='frpc') }}" class="btn btn-info">重启</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

    # 创建 config_frps.html
    cat > "$WEB_DIR/templates/config_frps.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>配置 FRP 服务端</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>配置 FRP 服务端</h1>
        <a href="{{ url_for('index') }}" class="btn btn-secondary mb-3">返回</a>
        <form method="POST">
            <div class="mb-3">
                <label for="bind_port" class="form-label">绑定端口</label>
                <input type="text" class="form-control" id="bind_port" name="bind_port" value="{{ config.get('common', {}).get('bind_port', '7000') }}">
            </div>
            <div class="mb-3">
                <label for="token" class="form-label">Token (留空随机生成)</label>
                <input type="text" class="form-control" id="token" name="token" value="{{ config.get('common', {}).get('token', '') }}">
            </div>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="enable_http" name="enable_http" {{ 'checked' if config.get('common', {}).get('vhost_http_port') else '' }}>
                <label class="form-check-label" for="enable_http">启用 HTTP/HTTPS 代理</label>
            </div>
            <div class="mb-3">
                <label for="vhost_http_port" class="form-label">HTTP 端口</label>
                <input type="text" class="form-control" id="vhost_http_port" name="vhost_http_port" value="{{ config.get('common', {}).get('vhost_http_port', '80') }}">
            </div>
            <div class="mb-3">
                <label for="vhost_https_port" class="form-label">HTTPS 端口</label>
                <input type="text" class="form-control" id="vhost_https_port" name="vhost_https_port" value="{{ config.get('common', {}).get('vhost_https_port', '443') }}">
            </div>
            <div class="mb-3">
                <label for="subdomain_host" class="form-label">二级域名主机 (如 frps.example.com)</label>
                <input type="text" class="form-control" id="subdomain_host" name="subdomain_host" value="{{ config.get('common', {}).get('subdomain_host', '') }}">
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF

    # 创建 config_frpc.html
    cat > "$WEB_DIR/templates/config_frpc.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>配置 FRP 客户端</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>配置 FRP 客户端</h1>
        <a href="{{ url_for('index') }}" class="btn btn-secondary mb-3">返回</a>
        <form method="POST">
            <div class="mb-3">
                <label for="server_addr" class="form-label">服务端 IP</label>
                <input type="text" class="form-control" id="server_addr" name="server_addr" value="{{ config.get('common', {}).get('server_addr', '') }}">
            </div>
            <div class="mb-3">
                <label for="server_port" class="form-label">服务端端口</label>
                <input type="text" class="form-control" id="server_port" name="server_port" value="{{ config.get('common', {}).get('server_port', '7000') }}">
            </div>
            <div class="mb-3">
                <label for="token" class="form-label">Token</label>
                <input type="text" class="form-control" id="token" name="token" value="{{ config.get('common', {}).get('token', '') }}">
            </div>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="enable_http" name="enable_http" {{ 'checked' if config.sections() and config[config.sections()[0]].get('type') in ['http', 'https'] else '' }}>
                <label class="form-check-label" for="enable_http">启用 HTTP/HTTPS 代理</label>
            </div>
            <div class="mb-3">
                <label for="service_name" class="form-label">服务名称</label>
                <input type="text" class="form-control" id="service_name" name="service_name" value="{{ config.sections()[0] if config.sections() else 'web' }}">
            </div>
            <div class="mb-3">
                <label for="local_ip" class="form-label">本地 IP</label>
                <input type="text" class="form-control" id="local_ip" name="local_ip" value="{{ config.get(config.sections()[0], {}).get('local_ip', '127.0.0.1') if config.sections() else '127.0.0.1' }}">
            </div>
            <div class="mb-3">
                <label for="local_port" class="form-label">本地端口</label>
                <input type="text" class="form-control" id="local_port" name="local_port" value="{{ config.get(config.sections()[0], {}).get('local_port', '') if config.sections() else '' }}">
            </div>
            <div class="mb-3">
                <label for="proxy_type" class="form-label">代理类型</label>
                <select class="form-control" id="proxy_type" name="proxy_type">
                    <option value="http" {{ 'selected' if config.get(config.sections()[0], {}).get('type', 'http') == 'http' else '' }}>HTTP</option>
                    <option value="https" {{ 'selected' if config.get(config.sections()[0], {}).get('type', '') == 'https' else '' }}>HTTPS</option>
                    <option value="tcp" {{ 'selected' if config.get(config.sections()[0], {}).get('type', '') == 'tcp' else '' }}>TCP</option>
                </select>
            </div>
            <div class="mb-3">
                <label for="custom_domains" class="form-label">自定义域名</label>
                <input type="text" class="form-control" id="custom_domains" name="custom_domains" value="{{ config.get(config.sections()[0], {}).get('custom_domains', '') if config.sections() else '' }}">
            </div>
            <div class="mb-3">
                <label for="subdomain" class="form-label">二级域名前缀</label>
                <input type="text" class="form-control" id="subdomain" name="subdomain" value="{{ config.get(config.sections()[0], {}).get('subdomain', '') if config.sections() else '' }}">
            </div>
            <div class="mb-3">
                <label for="remote_port" class="form-label">远程端口 (仅 TCP)</label>
                <input type="text" class="form-control" id="remote_port" name="remote_port" value="{{ config.get(config.sections()[0], {}).get('remote_port', '') if config.sections() else '' }}">
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF
}

# 创建 systemd 服务
create_systemd_services() {
    echo "创建 systemd 服务..."
    mkdir -p "$CONFIG_DIR"

    # frp-web 服务
    cat > /etc/systemd/system/frp-web.service <<EOF
[Unit]
Description=FRP Web Interface
After=network.target

[Service]
ExecStart=/usr/bin/python3 $WEB_DIR/frp_web.py
WorkingDirectory=$WEB_DIR
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # frps 服务
    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/frps -c $CONFIG_DIR/frps.ini
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # frpc 服务
    cat > /etc/systemd/system/frpc.service <<EOF
[Unit]
Description=FRP Client Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/frpc -c $CONFIG_DIR/frpc.ini
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable frp-web
    systemctl start frp-web
}

# 主流程
echo "开始一键部署 FRP Web 管理界面..."
install_dependencies
install_frp
install_flask
create_web_files
create_systemd_services

# 获取服务器 IP
SERVER_IP=$(hostname -I | awk '{print $1}')
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="127.0.0.1"
fi

# 提示
echo -e "${GREEN}部署完成！${NC}"
echo "请访问 Web 界面进行 FRP 配置：http://$SERVER_IP:$PYTHON_PORT"
echo "配置文件目录: $CONFIG_DIR"
echo "FRP 二进制: $INSTALL_DIR"
echo "检查服务状态: systemctl status frp-web frps frpc"
echo -e "${GREEN}通过 Web 界面可配置服务端（frps）或客户端（frpc），支持二级域名代理！${NC}"