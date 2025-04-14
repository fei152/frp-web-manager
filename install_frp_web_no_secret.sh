#!/bin/bash

# 一键部署 FRP Web 界面脚本，类似宝塔面板
FRP_VERSION="0.61.0"
FRP_URL="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz"
INSTALL_DIR="/usr/local/frp"
CONFIG_DIR="/etc/frp"
WEB_DIR="/opt/frp_web"
PYTHON_PORT_DEFAULT=5000
PYTHON_PORT=$PYTHON_PORT_DEFAULT
INSTALL_MODE=""
USERNAME=""
PASSWORD=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 检查命令
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# 检查端口是否被占用
check_port() {
    local port=$1
    netstat -tuln | grep ":$port " >/dev/null 2>&1
    return $?
}

# 清理端口占用
clear_port() {
    local port=$1
    echo "正在清理端口 $port 的占用..."
    local pid=$(netstat -tulnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1)
    if [[ -n "$pid" ]]; then
        kill -9 "$pid"
        echo "端口 $port 已清理。"
    else
        echo "端口 $port 未被占用，无需清理。"
    fi
}

# 随机生成用户名和密码
generate_random_credentials() {
    USERNAME=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
    PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
}

# 安装依赖
install_dependencies() {
    echo "检查并安装依赖..."
    if [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt install -y python3 python3-pip wget tar net-tools curl
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y python3 python3-pip wget tar net-tools curl
    else
        echo -e "${RED}不支持的系统，请手动安装 python3、pip3、wget、tar、net-tools、curl！${NC}"
        exit 1
    fi
}

# 安装 FRP
install_frp() {
    echo "正在下载 FRP v${FRP_VERSION}..."
    wget -q "$FRP_URL" -O frp.tar.gz
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}下载失败，请检查网络！${NC}"
        exit 1
    fi

    tar -xzf frp.tar.gz
    mkdir -p "$INSTALL_DIR"
    mv frp_${FRP_VERSION}_linux_amd64/frp* "$INSTALL_DIR/"
    rm -rf frp.tar.gz frp_${FRP_VERSION}_linux_amd64
    chmod +x "$INSTALL_DIR/frps" "$INSTALL_DIR/frpc"
}

# 安装 Python 依赖
install_python_packages() {
    echo "安装 Flask、tomlkit 和 flask-httpauth..."
    pip3 install flask tomlkit flask-httpauth
}

# 创建 Web 界面代码
create_web_files() {
    echo "创建 Web 界面文件..."
    mkdir -p "$WEB_DIR/templates"

    # 创建 frp_web.py（移除 SECRET_PATH，固定路由为 /admin/）
    cat > "$WEB_DIR/frp_web.py" <<EOF
from flask import Flask, render_template, request, redirect, flash, url_for, Response
from flask_httpauth import HTTPBasicAuth
import tomlkit
import os
import subprocess
import random
import string

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
auth = HTTPBasicAuth()

# 认证用户
users = {
    "$USERNAME": "$PASSWORD"
}

@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username
    return None

# 配置路径
CONFIG_DIR = "/etc/frp"
FRPS_CONFIG = os.path.join(CONFIG_DIR, "frps.toml")
FRPC_CONFIG = os.path.join(CONFIG_DIR, "frpc.toml")
INSTALL_DIR = "/usr/local/frp"

def get_service_status(service):
    try:
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
        return result.stdout.strip() == "active"
    except Exception as e:
        print(f"Error checking service {service}: {e}")
        return False

def restart_service(service):
    try:
        result = subprocess.run(["systemctl", "restart", service], capture_output=True, text=True)
        if result.returncode != 0:
            flash(f"重启 {service} 失败: {result.stderr}", "danger")
    except Exception as e:
        flash(f"重启 {service} 失败: {str(e)}", "danger")

@app.route('/')
def redirect_to_admin():
    return redirect(url_for('index', _external=True))

@app.route('/admin/')
@auth.login_required
def index():
    frps_status = get_service_status("frps")
    frpc_status = get_service_status("frpc")
    return render_template('index.html', frps_status=frps_status, frpc_status=frpc_status, install_mode="$INSTALL_MODE")

@app.route('/admin/config_frps', methods=['GET', 'POST'])
@auth.login_required
def config_frps():
    if request.method == 'POST':
        bind_port = request.form.get('bind_port', '7000')
        token = request.form.get('token') or ''.join(random.choices(string.hexdigits.lower(), k=16))
        enable_http = request.form.get('enable_http') == 'on'
        vhost_http_port = request.form.get('vhost_http_port', '8080') if enable_http else ''
        vhost_https_port = request.form.get('vhost_https_port', '8443') if enable_http else ''
        subdomain_host = request.form.get('subdomain_host', '') if enable_http else ''

        config = tomlkit.document()
        config['common'] = {
            'bind_port': int(bind_port),
            'token': token
        }
        if enable_http:
            config['common']['vhost_http_port'] = int(vhost_http_port)
            config['common']['vhost_https_port'] = int(vhost_https_port)
            if subdomain_host:
                config['common']['subdomain_host'] = subdomain_host

            cert_file = request.files.get('cert_file')
            key_file = request.files.get('key_file')
            if cert_file and key_file:
                cert_path = os.path.join(CONFIG_DIR, "frps.crt")
                key_path = os.path.join(CONFIG_DIR, "frps.key")
                cert_file.save(cert_path)
                key_file.save(key_path)
                os.chmod(cert_path, 0o644)
                os.chmod(key_path, 0o600)
                if 'webServer' not in config:
                    config['webServer'] = {}
                if 'tls' not in config['webServer']:
                    config['webServer']['tls'] = {}
                config['webServer']['tls']['certFile'] = cert_path
                config['webServer']['tls']['keyFile'] = key_path

        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FRPS_CONFIG, 'w') as f:
            tomlkit.dump(config, f)

        restart_service("frps")
        flash('服务端配置已保存并重启！', 'success')
        return redirect(url_for('index', _external=True))

    config = tomlkit.document()
    try:
        if os.path.exists(FRPS_CONFIG):
            with open(FRPS_CONFIG, 'r') as f:
                config = tomlkit.load(f)
    except Exception as e:
        flash(f'读取配置文件失败: {str(e)}', 'danger')
        config = tomlkit.document()
    return render_template('config_frps.html', config=config)

@app.route('/admin/config_frpc', methods=['GET', 'POST'])
@auth.login_required
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

        config = tomlkit.document()
        config['common'] = {
            'server_addr': server_addr,
            'server_port': int(server_port),
            'token': token
        }
        config['proxy'] = {}
        config['proxy'][service_name] = {
            'type': proxy_type,
            'local_ip': local_ip,
            'local_port': int(local_port)
        }
        if enable_http and custom_domains:
            config['proxy'][service_name]['custom_domains'] = custom_domains
        if enable_http and subdomain:
            config['proxy'][service_name]['subdomain'] = subdomain
        if not enable_http and remote_port:
            config['proxy'][service_name]['remote_port'] = int(remote_port)

        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FRPC_CONFIG, 'w') as f:
            tomlkit.dump(config, f)

        restart_service("frpc")
        flash('客户端配置已保存并重启！', 'success')
        return redirect(url_for('index', _external=True))

    config = tomlkit.document()
    if os.path.exists(FRPC_CONFIG):
        with open(FRPC_CONFIG, 'r') as f:
            config = tomlkit.load(f)
    return render_template('config_frpc.html', config=config)

@app.route('/admin/text_frps', methods=['GET', 'POST'])
@auth.login_required
def text_frps():
    if request.method == 'POST':
        config_text = request.form.get('config_text')
        try:
            tomlkit.loads(config_text)
            with open(FRPS_CONFIG, 'w') as f:
                f.write(config_text)
            restart_service("frps")
            flash('服务端配置已保存并重启！', 'success')
        except Exception as e:
            flash(f'保存失败，无效的 TOML 格式: {str(e)}', 'danger')
        return redirect(url_for('text_frps', _external=True))

    config_text = ""
    if os.path.exists(FRPS_CONFIG):
        with open(FRPS_CONFIG, 'r') as f:
            config_text = f.read()
    return render_template('text_frps.html', config_text=config_text)

@app.route('/admin/text_frpc', methods=['GET', 'POST'])
@auth.login_required
def text_frpc():
    if request.method == 'POST':
        config_text = request.form.get('config_text')
        try:
            tomlkit.loads(config_text)
            with open(FRPC_CONFIG, 'w') as f:
                f.write(config_text)
            restart_service("frpc")
            flash('客户端配置已保存并重启！', 'success')
        except Exception as e:
            flash(f'保存失败，无效的 TOML 格式: {str(e)}', 'danger')
        return redirect(url_for('text_frpc', _external=True))

    config_text = ""
    if os.path.exists(FRPC_CONFIG):
        with open(FRPC_CONFIG, 'r') as f:
            config_text = f.read()
    return render_template('text_frpc.html', config_text=config_text)

@app.route('/admin/generate_frpc', methods=['GET', 'POST'])
@auth.login_required
def generate_frpc():
    frps_config = tomlkit.document()
    has_subdomain_host = False
    server_addr = ""
    server_port = "7000"
    token = ""

    try:
        if os.path.exists(FRPS_CONFIG):
            with open(FRPS_CONFIG, 'r') as f:
                frps_config = tomlkit.load(f)
                server_port = str(frps_config.get('common', {}).get('bind_port', '7000'))
                token = frps_config.get('common', {}).get('token', '')
                has_subdomain_host = 'subdomain_host' in frps_config.get('common', {})
    except Exception as e:
        flash(f'读取服务端配置文件失败: {str(e)}', 'danger')

    try:
        server_addr = subprocess.check_output("curl -s ifconfig.me", shell=True).decode('utf-8').strip()
    except:
        server_addr = "127.0.0.1"

    if request.method == 'POST':
        server_addr = request.form.get('server_addr', server_addr)
        server_port = request.form.get('server_port', server_port)
        token = request.form.get('token', token)

        clients = []
        client_count = int(request.form.get('client_count', 1))
        for i in range(client_count):
            service_name = request.form.get(f'service_name_{i}', f'client_{i}')
            local_ip = request.form.get(f'local_ip_{i}', '127.0.0.1')
            local_port = request.form.get(f'local_port_{i}', '')
            proxy_type = request.form.get(f'proxy_type_{i}', 'tcp')
            custom_domains = request.form.get(f'custom_domains_{i}', '')
            subdomain = request.form.get(f'subdomain_{i}', '')
            remote_port = request.form.get(f'remote_port_{i}', '')

            if not local_port:
                continue

            client_config = {
                'service_name': service_name,
                'local_ip': local_ip,
                'local_port': local_port,
                'proxy_type': proxy_type,
                'custom_domains': custom_domains,
                'subdomain': subdomain,
                'remote_port': remote_port
            }
            clients.append(client_config)

        config = tomlkit.document()
        config['common'] = {
            'server_addr': server_addr,
            'server_port': int(server_port),
            'token': token
        }
        config['proxy'] = {}
        for client in clients:
            service_name = client['service_name']
            config['proxy'][service_name] = {
                'type': client['proxy_type'],
                'local_ip': client['local_ip'],
                'local_port': int(client['local_port'])
            }
            if client['proxy_type'] in ['http', 'https']:
                if client['custom_domains']:
                    config['proxy'][service_name]['custom_domains'] = client['custom_domains']
                if client['subdomain'] and has_subdomain_host:
                    config['proxy'][service_name]['subdomain'] = client['subdomain']
            else:
                if client['remote_port']:
                    config['proxy'][service_name]['remote_port'] = int(client['remote_port'])

        config_text = tomlkit.dumps(config)

        if 'download' in request.form:
            return Response(
                config_text,
                mimetype='text/plain',
                headers={"Content-disposition": "attachment; filename=frpc.toml"}
            )

        return render_template('generate_frpc.html', 
                               server_addr=server_addr,
                               server_port=server_port,
                               token=token,
                               has_subdomain_host=has_subdomain_host,
                               config_text=config_text,
                               clients=clients)

    return render_template('generate_frpc.html', 
                           server_addr=server_addr,
                           server_port=server_port,
                           token=token,
                           has_subdomain_host=has_subdomain_host,
                           config_text=None,
                           clients=[{'service_name': 'web', 'local_ip': '127.0.0.1', 'local_port': '', 'proxy_type': 'tcp', 'custom_domains': '', 'subdomain': '', 'remote_port': ''}])

@app.route('/admin/service/<action>/<service>')
@auth.login_required
def service_action(action, service):
    if action in ['start', 'stop', 'restart']:
        subprocess.run([f"systemctl {action} {service}"], shell=True, capture_output=True)
        flash(f"{service} 已{action}！", 'success')
    return redirect(url_for('index', _external=True))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=$PYTHON_PORT)
EOF

    # 创建 index.html
    cat > "$WEB_DIR/templates/index.html" <<EOF
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
            {% if install_mode == "both" or install_mode == "frps" %}
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
            {% endif %}
            {% if install_mode == "both" or install_mode == "frpc" %}
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
            {% endif %}
        </div>
        <div class="row mt-4">
            <div class="col-md-12">
                <a href="{{ url_for('generate_frpc') }}" class="btn btn-secondary">客户端配置生成器</a>
            </div>
        </div>
    </div>
</body>
</html>
EOF

    # 创建 config_frps.html
    cat > "$WEB_DIR/templates/config_frps.html" <<EOF
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
        <a href="{{ url_for('text_frps') }}" class="btn btn-info mb-3">文本编辑</a>
        <form method="POST" enctype="multipart/form-data">
            <div class="mb-3">
                <label for="bind_port" class="form-label">绑定端口（用于 TCP 转发，例如 7000）</label>
                <input type="text" class="form-control" id="bind_port" name="bind_port" value="{{ config.get('common', {}).get('bind_port', '7000') }}">
            </div>
            <div class="mb-3">
                <label for="token" class="form-label">Token（留空随机生成）</label>
                <input type="text" class="form-control" id="token" name="token" value="{{ config.get('common', {}).get('token', '') }}">
            </div>
            <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="enable_http" name="enable_http" {{ 'checked' if config.get('common', {}).get('vhost_http_port') else '' }}>
                <label class="form-check-label" for="enable_http">启用 HTTP/HTTPS 代理</label>
            </div>
            <div class="mb-3">
                <label for="vhost_http_port" class="form-label">HTTP 端口（例如 8080，需确保未被占用）</label>
                <input type="text" class="form-control" id="vhost_http_port" name="vhost_http_port" value="{{ config.get('common', {}).get('vhost_http_port', '8080') }}">
            </div>
            <div class="mb-3">
                <label for="vhost_https_port" class="form-label">HTTPS 端口（例如 8443，需确保未被占用）</label>
                <input type="text" class="form-control" id="vhost_https_port" name="vhost_https_port" value="{{ config.get('common', {}).get('vhost_https_port', '8443') }}">
            </div>
            <div class="mb-3">
                <label for="cert_file" class="form-label">SSL 证书文件（.crt 或 .pem，用于 HTTPS）</label>
                <input type="file" class="form-control" id="cert_file" name="cert_file">
            </div>
            <div class="mb-3">
                <label for="key_file" class="form-label">SSL 私钥文件（.key 或 .pem，用于 HTTPS）</label>
                <input type="file" class="form-control" id="key_file" name="key_file">
            </div>
            <div class="mb-3">
                <label for="subdomain_host" class="form-label">二级域名主机（可选，例如 frps.example.com，留空则客户端需指定完整域名）</label>
                <input type="text" class="form-control" id="subdomain_host" name="subdomain_host" value="{{ config.get('common', {}).get('subdomain_host', '') }}" placeholder="留空则客户端需指定完整域名">
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF

    # 创建 config_frpc.html
    cat > "$WEB_DIR/templates/config_frpc.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>配置 FRP 客户端</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function toggleFields() {
            var proxyType = document.getElementById("proxy_type").value;
            var httpFields = document.getElementById("http_fields");
            var tcpFields = document.getElementById("tcp_fields");
            if (proxyType === "tcp") {
                httpFields.style.display = "none";
                tcpFields.style.display = "block";
            } else {
                httpFields.style.display = "block";
                tcpFields.style.display = "none";
            }
        }
    </script>
</head>
<body onload="toggleFields()">
    <div class="container mt-5">
        <h1>配置 FRP 客户端</h1>
        <a href="{{ url_for('index') }}" class="btn btn-secondary mb-3">返回</a>
        <a href="{{ url_for('text_frpc') }}" class="btn btn-info mb-3">文本编辑</a>
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
            <div class="mb-3">
                <label for="service_name" class="form-label">服务名称（唯一标识，例如 ssh 或 web）</label>
                <input type="text" class="form-control" id="service_name" name="service_name" value="web">
            </div>
            <div class="mb-3">
                <label for="local_ip" class="form-label">本地 IP（映射到的本地服务 IP，例如 127.0.0.1）</label>
                <input type="text" class="form-control" id="local_ip" name="local_ip" value="{{ config.get('proxy', {}).get('web', {}).get('local_ip', '127.0.0.1') }}">
            </div>
            <div class="mb-3">
                <label for="local_port" class="form-label">本地端口（映射到的本地服务端口，例如 8080 或 22）</label>
                <input type="text" class="form-control" id="local_port" name="local_port" value="{{ config.get('proxy', {}).get('web', {}).get('local_port', '') }}">
            </div>
            <div class="mb-3">
                <label for="proxy_type" class="form-label">代理类型</label>
                <select class="form-control" id="proxy_type" name="proxy_type" onchange="toggleFields()">
                    <option value="http" {{ 'selected' if config.get('proxy', {}).get('web', {}).get('type', 'http') == 'http' else '' }}>HTTP</option>
                    <option value="https" {{ 'selected' if config.get('proxy', {}).get('web', {}).get('type', '') == 'https' else '' }}>HTTPS</option>
                    <option value="tcp" {{ 'selected' if config.get('proxy', {}).get('web', {}).get('type', '') == 'tcp' else '' }}>TCP</option>
                </select>
            </div>
            <div id="http_fields">
                <div class="mb-3 form-check">
                    <input type="checkbox" class="form-check-input" id="enable_http" name="enable_http" {{ 'checked' if config.get('proxy', {}).get('web', {}).get('type') in ['http', 'https'] else '' }}>
                    <label class="form-check-label" for="enable_http">启用 HTTP/HTTPS 代理</label>
                </div>
                <div class="mb-3">
                    <label for="custom_domains" class="form-label">自定义域名（HTTP/HTTPS 模式下使用，例如 test.example.com）</label>
                    <input type="text" class="form-control" id="custom_domains" name="custom_domains" value="{{ config.get('proxy', {}).get('web', {}).get('custom_domains', '') }}">
                </div>
                <div class="mb-3">
                    <label for="subdomain" class="form-label">二级域名前缀（仅当服务端设置了二级域名主机时有效，例如 test）</label>
                    <input type="text" class="form-control" id="subdomain" name="subdomain" value="{{ config.get('proxy', {}).get('web', {}).get('subdomain', '') }}">
                </div>
            </div>
            <div id="tcp_fields" style="display: none;">
                <div class="mb-3">
                    <label for="remote_port" class="form-label">远程端口（TCP 模式下使用，例如 2222，用于外部访问）</label>
                    <input type="text" class="form-control" id="remote_port" name="remote_port" value="{{ config.get('proxy', {}).get('web', {}).get('remote_port', '') }}">
                </div>
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF

    # 创建 text_frps.html
    cat > "$WEB_DIR/templates/text_frps.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>文本编辑 FRP 服务端配置</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>文本编辑 FRP 服务端配置</h1>
        <a href="{{ url_for('config_frps') }}" class="btn btn-secondary mb-3">返回 UI 编辑</a>
        <form method="POST">
            <div class="mb-3">
                <label for="config_text" class="form-label">服务端配置文件 (frps.toml)</label>
                <textarea class="form-control" id="config_text" name="config_text" rows="20">{{ config_text }}</textarea>
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF

    # 创建 text_frpc.html
    cat > "$WEB_DIR/templates/text_frpc.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>文本编辑 FRP 客户端配置</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>文本编辑 FRP 客户端配置</h1>
        <a href="{{ url_for('config_frpc') }}" class="btn btn-secondary mb-3">返回 UI 编辑</a>
        <form method="POST">
            <div class="mb-3">
                <label for="config_text" class="form-label">客户端配置文件 (frpc.toml)</label>
                <textarea class="form-control" id="config_text" name="config_text" rows="20">{{ config_text }}</textarea>
            </div>
            <button type="submit" class="btn btn-primary">保存并重启</button>
        </form>
    </div>
</body>
</html>
EOF

    # 创建 generate_frpc.html（支持多客户端配置和复制功能）
    cat > "$WEB_DIR/templates/generate_frpc.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>FRP 客户端配置生成器</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1>FRP 客户端配置生成器</h1>
        <a href="{{ url_for('index') }}" class="btn btn-secondary mb-3">返回</a>
        <form method="POST">
            <h3>服务端信息（从 frps.toml 自动读取）</h3>
            <div class="mb-3">
                <label for="server_addr" class="form-label">服务端 IP</label>
                <input type="text" class="form-control" id="server_addr" name="server_addr" value="{{ server_addr }}">
            </div>
            <div class="mb-3">
                <label for="server_port" class="form-label">服务端端口</label>
                <input type="text" class="form-control" id="server_port" name="server_port" value="{{ server_port }}">
            </div>
            <div class="mb-3">
                <label for="token" class="form-label">Token</label>
                <input type="text" class="form-control" id="token" name="token" value="{{ token }}">
            </div>
            <h3>客户端配置</h3>
            <div id="clients_container">
                {% for client in clients %}
                <div class="client-section mb-4 p-3 border rounded" id="client_{{ loop.index0 }}">
                    <h4>客户端配置 #{{ loop.index }}</h4>
                    {% if loop.index0 > 0 %}
                    <button type="button" class="btn btn-danger mb-3" onclick="removeClient({{ loop.index0 }})">删除客户端</button>
                    {% endif %}
                    <div class="mb-3">
                        <label for="service_name_{{ loop.index0 }}" class="form-label">服务名称（唯一标识，例如 ssh 或 web）</label>
                        <input type="text" class="form-control" id="service_name_{{ loop.index0 }}" name="service_name_{{ loop.index0 }}" value="{{ client.service_name }}">
                    </div>
                    <div class="mb-3">
                        <label for="local_ip_{{ loop.index0 }}" class="form-label">本地 IP（映射到的本地服务 IP，例如 127.0.0.1）</label>
                        <input type="text" class="form-control" id="local_ip_{{ loop.index0 }}" name="local_ip_{{ loop.index0 }}" value="{{ client.local_ip }}">
                    </div>
                    <div class="mb-3">
                        <label for="local_port_{{ loop.index0 }}" class="form-label">本地端口（映射到的本地服务端口，例如 8080 或 22）</label>
                        <input type="text" class="form-control" id="local_port_{{ loop.index0 }}" name="local_port_{{ loop.index0 }}" value="{{ client.local_port }}">
                    </div>
                    <div class="mb-3">
                        <label for="proxy_type_{{ loop.index0 }}" class="form-label">代理类型</label>
                        <select class="form-control" id="proxy_type_{{ loop.index0 }}" name="proxy_type_{{ loop.index0 }}" onchange="toggleFields({{ loop.index0 }})">
                            <option value="tcp" {{ 'selected' if client.proxy_type == 'tcp' else '' }}>TCP</option>
                            <option value="http" {{ 'selected' if client.proxy_type == 'http' else '' }}>HTTP</option>
                            <option value="https" {{ 'selected' if client.proxy_type == 'https' else '' }}>HTTPS</option>
                        </select>
                    </div>
                    <div id="http_fields_{{ loop.index0 }}" style="display: none;">
                        <div class="mb-3">
                            <label for="custom_domains_{{ loop.index0 }}" class="form-label">自定义域名（HTTP/HTTPS 模式下使用，例如 test.example.com）</label>
                            <input type="text" class="form-control" id="custom_domains_{{ loop.index0 }}" name="custom_domains_{{ loop.index0 }}" value="{{ client.custom_domains }}">
                        </div>
                        <div class="mb-3" id="subdomain_field_{{ loop.index0 }}" style="display: none;">
                            <label for="subdomain_{{ loop.index0 }}" class="form-label">二级域名前缀（服务端已设置二级域名主机，例如 test）</label>
                            <input type="text" class="form-control" id="subdomain_{{ loop.index0 }}" name="subdomain_{{ loop.index0 }}" value="{{ client.subdomain }}">
                        </div>
                    </div>
                    <div id="tcp_fields_{{ loop.index0 }}" style="display: block;">
                        <div class="mb-3">
                            <label for="remote_port_{{ loop.index0 }}" class="form-label">远程端口（TCP 模式下使用，例如 2222，用于外部访问）</label>
                            <input type="text" class="form-control" id="remote_port_{{ loop.index0 }}" name="remote_port_{{ loop.index0 }}" value="{{ client.remote_port }}">
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
            <input type="hidden" id="client_count" name="client_count" value="{{ clients|length }}">
            <button type="button" class="btn btn-primary mb-3" id="add_client_btn">新增客户端</button>
            <br>
            <button type="submit" class="btn btn-primary">生成配置文件</button>
        </form>

        {% if config_text %}
        <div class="mt-4">
            <h3>生成的配置文件 (frpc.toml)</h3>
            <pre id="config_text">{{ config_text }}</pre>
            <button type="button" class="btn btn-info" onclick="copyConfig()">复制配置文件</button>
            <form method="POST" style="display: inline;">
                <input type="hidden" name="server_addr" value="{{ server_addr }}">
                <input type="hidden" name="server_port" value="{{ server_port }}">
                <input type="hidden" name="token" value="{{ token }}">
                {% for client in clients %}
                <input type="hidden" name="service_name_{{ loop.index0 }}" value="{{ client.service_name }}">
                <input type="hidden" name="local_ip_{{ loop.index0 }}" value="{{ client.local_ip }}">
                <input type="hidden" name="local_port_{{ loop.index0 }}" value="{{ client.local_port }}">
                <input type="hidden" name="proxy_type_{{ loop.index0 }}" value="{{ client.proxy_type }}">
                <input type="hidden" name="custom_domains_{{ loop.index0 }}" value="{{ client.custom_domains }}">
                <input type="hidden" name="subdomain_{{ loop.index0 }}" value="{{ client.subdomain }}">
                <input type="hidden" name="remote_port_{{ loop.index0 }}" value="{{ client.remote_port }}">
                {% endfor %}
                <input type="hidden" name="client_count" value="{{ clients|length }}">
                <button type="submit" name="download" class="btn btn-success">下载 frpc.toml</button>
            </form>
        </div>
        {% endif %}
    </div>

    <script>
        let clientCount = {{ clients|length - 1 if clients else 0 }};

        function toggleFields(index) {
            console.log("toggleFields called for index:", index);
            var proxyType = document.getElementById("proxy_type_" + index).value;
            var httpFields = document.getElementById("http_fields_" + index);
            var tcpFields = document.getElementById("tcp_fields_" + index);
            if (proxyType === "tcp") {
                httpFields.style.display = "none";
                tcpFields.style.display = "block";
            } else {
                httpFields.style.display = "block";
                tcpFields.style.display = "none";
            }
            toggleSubdomainField(index);
        }

        function toggleSubdomainField(index) {
            console.log("toggleSubdomainField called for index:", index);
            var hasSubdomainHost = {{ 'true' if has_subdomain_host else 'false' }};
            var proxyType = document.getElementById("proxy_type_" + index).value;
            var subdomainField = document.getElementById("subdomain_field_" + index);
            if (hasSubdomainHost && (proxyType === "http" || proxyType === "https")) {
                subdomainField.style.display = "block";
            } else {
                subdomainField.style.display = "none";
            }
        }

        function addClient() {
            console.log("addClient called, current clientCount:", clientCount);
            clientCount++;
            var container = document.getElementById("clients_container");
            if (!container) {
                console.error("clients_container not found!");
                return;
            }

            var clientDiv = document.createElement("div");
            clientDiv.className = "client-section mb-4 p-3 border rounded";
            clientDiv.id = "client_" + clientCount;
            clientDiv.innerHTML = \`
                <h4>客户端配置 #\${clientCount + 1}</h4>
                <button type="button" class="btn btn-danger mb-3" onclick="removeClient(\${clientCount})">删除客户端</button>
                <div class="mb-3">
                    <label for="service_name_\${clientCount}" class="form-label">服务名称（唯一标识，例如 ssh 或 web）</label>
                    <input type="text" class="form-control" id="service_name_\${clientCount}" name="service_name_\${clientCount}" value="client_\${clientCount}">
                </div>
                <div class="mb-3">
                    <label for="local_ip_\${clientCount}" class="form-label">本地 IP（映射到的本地服务 IP，例如 127.0.0.1）</label>
                    <input type="text" class="form-control" id="local_ip_\${clientCount}" name="local_ip_\${clientCount}" value="127.0.0.1">
                </div>
                <div class="mb-3">
                    <label for="local_port_\${clientCount}" class="form-label">本地端口（映射到的本地服务端口，例如 8080 或 22）</label>
                    <input type="text" class="form-control" id="local_port_\${clientCount}" name="local_port_\${clientCount}" value="">
                </div>
                <div class="mb-3">
                    <label for="proxy_type_\${clientCount}" class="form-label">代理类型</label>
                    <select class="form-control" id="proxy_type_\${clientCount}" name="proxy_type_\${clientCount}" onchange="toggleFields(\${clientCount})">
                        <option value="tcp">TCP</option>
                        <option value="http">HTTP</option>
                        <option value="https">HTTPS</option>
                    </select>
                </div>
                <div id="http_fields_\${clientCount}" style="display: none;">
                    <div class="mb-3">
                        <label for="custom_domains_\${clientCount}" class="form-label">自定义域名（HTTP/HTTPS 模式下使用，例如 test.example.com）</label>
                        <input type="text" class="form-control" id="custom_domains_\${clientCount}" name="custom_domains_\${clientCount}" value="">
                    </div>
                    <div class="mb-3" id="subdomain_field_\${clientCount}" style="display: none;">
                        <label for="subdomain_\${clientCount}" class="form-label">二级域名前缀（服务端已设置二级域名主机，例如 test）</label>
                        <input type="text" class="form-control" id="subdomain_\${clientCount}" name="subdomain_\${clientCount}" value="">
                    </div>
                </div>
                <div id="tcp_fields_\${clientCount}" style="display: block;">
                    <div class="mb-3">
                        <label for="remote_port_\${clientCount}" class="form-label">远程端口（TCP 模式下使用，例如 2222，用于外部访问）</label>
                        <input type="text" class="form-control" id="remote_port_\${clientCount}" name="remote_port_\${clientCount}" value="">
                    </div>
                </div>
            \`;
            container.appendChild(clientDiv);
            document.getElementById("client_count").value = clientCount + 1;
            console.log("New client added, updated clientCount:", clientCount);
            toggleFields(clientCount);
        }

        function removeClient(index) {
            console.log("removeClient called for index:", index);
            var clientDiv = document.getElementById("client_" + index);
            if (clientDiv) {
                clientDiv.remove();
                console.log("Client removed, index:", index);
            } else {
                console.error("Client div not found for index:", index);
            }
        }

        function copyConfig() {
            console.log("copyConfig called");
            var configText = document.getElementById("config_text").innerText;
            navigator.clipboard.writeText(configText).then(function() {
                alert("配置文件内容已复制到剪贴板！");
            }, function() {
                alert("复制失败，请手动复制！");
            });
        }

        document.addEventListener("DOMContentLoaded", function() {
            console.log("DOM fully loaded, initializing fields...");
            {% for i in range(clients|length) %}
                toggleFields({{ i }});
                toggleSubdomainField({{ i }});
            {% endfor %}

            var addClientBtn = document.getElementById("add_client_btn");
            if (addClientBtn) {
                addClientBtn.addEventListener("click", addClient);
                console.log("addClientBtn event listener added");
            } else {
                console.error("add_client_btn not found!");
            }
        });
    </script>
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

    # 根据安装模式创建 frps 和 frpc 服务
    if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frps" ]]; then
        cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=FRP Server Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/frps -c $CONFIG_DIR/frps.toml
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    fi

    if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frpc" ]]; then
        cat > /etc/systemd/system/frpc.service <<EOF
[Unit]
Description=FRP Client Service
After=network.target

[Service]
ExecStart=$INSTALL_DIR/frpc -c $CONFIG_DIR/frpc.toml
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable frp-web
    systemctl start frp-web

    # 启动 frps 和 frpc 服务（如果安装）
    if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frps" ]]; then
        systemctl enable frps
        systemctl start frps
    fi
    if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frpc" ]]; then
        systemctl enable frpc
        systemctl start frpc
    fi
}

# 清理旧环境（仅清理 FRP 相关，不影响其他端口）
cleanup_old_install() {
    echo "清理旧 FRP 安装环境..."
    systemctl stop frp-web frps frpc 2>/dev/null
    systemctl disable frp-web frps frpc 2>/dev/null
    rm -rf "$CONFIG_DIR" "$WEB_DIR" "$INSTALL_DIR"
    rm -f /etc/systemd/system/frp-web.service /etc/systemd/system/frps.service /etc/systemd/system/frpc.service
    systemctl daemon-reload
}

# 主流程
echo "开始一键部署 FRP Web 管理界面..."

# 选择安装模式
while true; do
    echo "请选择安装模式："
    echo "1) 仅安装 frps（服务端）"
    echo "2) 仅安装 frpc（客户端）"
    echo "3) 安装 frps 和 frpc（两者都要）"
    read -p "请输入选项（1-3）： " mode
    case $mode in
        1)
            INSTALL_MODE="frps"
            break
            ;;
        2)
            INSTALL_MODE="frpc"
            break
            ;;
        3)
            INSTALL_MODE="both"
            break
            ;;
        *)
            echo -e "${RED}无效选项，请输入 1、2 或 3！${NC}"
            ;;
    esac
done

# 检查 Web 端口（5000）
if check_port "$PYTHON_PORT_DEFAULT"; then
    echo -e "${RED}端口 $PYTHON_PORT_DEFAULT 已被占用！${NC}"
    read -p "是否清理 $PYTHON_PORT_DEFAULT 端口的占用？（y/n，默认 n）： " CLEAR_WEB_PORT
    CLEAR_WEB_PORT=${CLEAR_WEB_PORT:-n}
    if [[ "$CLEAR_WEB_PORT" =~ ^[Yy]$ ]]; then
        clear_port "$PYTHON_PORT_DEFAULT"
        PYTHON_PORT=$PYTHON_PORT_DEFAULT
    else
        while true; do
            read -p "请输入新的 Web 界面端口： " PYTHON_PORT
            if ! [[ "$PYTHON_PORT" =~ ^[0-9]+$ ]] || [ "$PYTHON_PORT" -lt 1 ] || [ "$PYTHON_PORT" -gt 65535 ]; then
                echo -e "${RED}端口号必须在 1-65535 之间！${NC}"
                continue
            fi
            if check_port "$PYTHON_PORT"; then
                echo -e "${RED}端口 $PYTHON_PORT 已被占用，请选择其他端口！${NC}"
                continue
            fi
            break
        done
    fi
else
    echo "端口 $PYTHON_PORT_DEFAULT 未被占用，将使用默认端口。"
    read -p "是否更改默认 Web 界面端口 $PYTHON_PORT_DEFAULT？（y/n，默认 n）： " CHANGE_PORT
    CHANGE_PORT=${CHANGE_PORT:-n}
    if [[ "$CHANGE_PORT" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "请输入新的 Web 界面端口： " PYTHON_PORT
            if ! [[ "$PYTHON_PORT" =~ ^[0-9]+$ ]] || [ "$PYTHON_PORT" -lt 1 ] || [ "$PYTHON_PORT" -gt 65535 ]; then
                echo -e "${RED}端口号必须在 1-65535 之间！${NC}"
                continue
            fi
            if check_port "$PYTHON_PORT"; then
                echo -e "${RED}端口 $PYTHON_PORT 已被占用，请选择其他端口！${NC}"
                continue
            fi
            break
        done
    else
        PYTHON_PORT=$PYTHON_PORT_DEFAULT
    fi
fi

# 检查 80 和 443 端口是否被占用，并询问是否清理
CLEAR_PORTS=""
if check_port 80 || check_port 443; then
    echo -e "${RED}警告：端口 80 和/或 443 已被占用！${NC}"
    read -p "是否清理 80 和 443 端口的占用？（y/n，默认 n）： " CLEAR_PORTS
    CLEAR_PORTS=${CLEAR_PORTS:-n}
    if [[ "$CLEAR_PORTS" =~ ^[Yy]$ ]]; then
        if check_port 80; then
            clear_port 80
        fi
        if check_port 443; then
            clear_port 443
        fi
    else
        echo "跳过清理 80 和 443 端口，Web 界面默认使用 8080 和 8443 端口。"
    fi
fi

# 提示用户输入 Web 界面的用户名和密码
echo "设置 Web 界面的访问认证信息："
read -p "请输入 Web 界面的用户名（直接回车随机生成）： " USERNAME
read -p "请输入 Web 界面的密码（直接回车随机生成）： " PASSWORD

# 如果用户未输入，则随机生成
if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "未输入完整信息，将随机生成..."
    generate_random_credentials
fi

# 保存认证信息到文件
cat > "$CONFIG_DIR/web_credentials.txt" <<EOF
Web 界面认证信息：
用户名: $USERNAME
密码: $PASSWORD
EOF

# 清理旧环境
cleanup_old_install

# 安装依赖和 FRP
install_dependencies
install_frp
install_python_packages
create_web_files
create_systemd_services

# 授权低端口（如果用户选择清理 80 和 443）
if [[ "$CLEAR_PORTS" =~ ^[Yy]$ ]]; then
    setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/frps"
fi

# 获取服务器内网和公网 IP
SERVER_LAN_IP=$(hostname -I | awk '{print $1}')
if [[ -z "$SERVER_LAN_IP" ]]; then
    SERVER_LAN_IP="127.0.0.1"
fi
SERVER_WAN_IP=$(curl -s ifconfig.me)
if [[ -z "$SERVER_WAN_IP" ]]; then
    SERVER_WAN_IP="无法获取公网 IP，请检查网络"
fi

# 提示
echo -e "${GREEN}部署完成！${NC}"
echo "请访问 Web 界面进行 FRP 配置："
echo "内网地址: http://$SERVER_LAN_IP:$PYTHON_PORT/admin/"
echo "公网地址: http://$SERVER_WAN_IP:$PYTHON_PORT/admin/"
echo "Web 界面认证信息："
echo "用户名: $USERNAME"
echo "密码: $PASSWORD"
echo "如需查看认证信息，请运行以下命令："
echo "  cat $CONFIG_DIR/web_credentials.txt"
echo "配置文件目录: $CONFIG_DIR"
echo "FRP 二进制: $INSTALL_DIR"
echo "检查服务状态: systemctl status frp-web"
if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frps" ]]; then
    echo "检查 frps 状态: systemctl status frps"
fi
if [[ "$INSTALL_MODE" == "both" || "$INSTALL_MODE" == "frpc" ]]; then
    echo "检查 frpc 状态: systemctl status frpc"
fi
echo -e "${GREEN}通过 Web 界面可配置服务端（frps）或客户端（frpc），支持 TCP 转发和 HTTPS（需上传 SSL 证书）！${NC}"
