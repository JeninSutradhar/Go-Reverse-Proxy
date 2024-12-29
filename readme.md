### **What This Code Does**
1. **Public Server** (`public_server.go`):
   - Acts as a **central hub** for tunneling traffic between a client (browser or external user) and a local server (behind NAT).
   - **WebSocket** connections:
     - Local servers connect to this public server using WebSocket.
     - Public server maintains a map of active WebSocket connections and routes requests accordingly.
   - **Reverse Proxy**:
     - Routes HTTP(S) requests to the appropriate local server based on active connections.
   - **Additional Features**:
     - IP whitelisting (restricts access to allowed CIDRs).
     - Rate limiting using `golang.org/x/time/rate`.
     - Prometheus metrics for monitoring.

2. **Local Server** (`local_server.go`):
   - Connects to the **public server** over WebSocket.
   - Forwards any requests received via the public server to its own local HTTP server.
   - Automatically attempts to reconnect if disconnected.

---

### **How It Works**
1. **Setup**:
   - You deploy `public_server.go` on a VPS with a public IP.
   - You run `local_server.go` on your local machine (behind NAT or firewall).
   - Local server connects to the public server's WebSocket endpoint.

2. **Traffic Flow**:
   - A user sends a request to the public server's address.
   - The public server proxies this request to the local server over the WebSocket connection.
   - The local server processes the request and sends the response back to the public server, which forwards it to the user.

---

### **Features**
1. **WebSocket Communication**:
   - Efficient and keeps connections alive for real-time communication.

2. **Round-Robin Load Balancing**:
   - Balances traffic between multiple local servers.

3. **Prometheus Metrics**:
   - Exposes metrics for monitoring active connections and request counts.

4. **Security Features**:
   - TLS support for encrypted communication.
   - IP whitelisting and rate limiting.

---

### **What You Can Use This For**
- **Webhook Testing**:
  - Similar to ngrok, expose a local development server for webhook integration.
- **Remote Access**:
  - Access your local server (e.g., dashboard or API) from anywhere.
- **Load Balancing**:
  - Distribute incoming requests to multiple local servers.
- **Custom Proxy**:
  - Tailor it to your needs (e.g., adding authentication or specific routing rules).

---

# USAGE

### **Prerequisites**
1. **Local Machine (Kali Linux):**
   - Install **Golang**: Ensure you have Go installed. Verify with `go version`.
   - Install `git`: Use `sudo apt install git` to get Git for cloning repositories.
   - Open necessary ports for your local server (default: `3000`).

2. **Server (Ubuntu VM):**
   - Install **aaPanel**: if it's already installed, you can use it to manage configurations like firewalls, certificates, and server monitoring.
   - Open required ports in **Azure's Network Security Group (NSG)**:
     - **8080**: HTTP public server.
     - **8443**: HTTPS public server (if TLS enabled).
     - **9090**: Metrics server for Prometheus.

---

### **Server-Side Setup (Azure VM)**

#### 1. **Install Dependencies**
   - **Update the system**:
     ```bash
     sudo apt update && sudo apt upgrade -y
     ```
   - **Install Go**:
     ```bash
     sudo apt install golang -y
     go version  # Confirm installation
     ```
   - **Install Git**:
     ```bash
     sudo apt install git -y
     ```

#### 2. **Set Up Project Files**
   - Clone your repository or create a new directory:
     ```bash
     git clone https://github.com/JeninSutradhar/Go-Reverse-Proxy
     cd Go-Reverse-Proxy
     ```
   - Create or modify the `config.yaml` file:
     ```yaml
     local_servers:
       - "http://localhost:3000"  # Replace with your local machine's server address if needed
     whitelist_cidr:
       - "0.0.0.0/0"  # Allow all (or replace with specific CIDRs for security)
     rate_limit: 100
     ```
   - Generate TLS certificates (optional, for HTTPS):
     ```bash
     sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt \
     -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=yourdomain.com"
     ```

#### 3. **Run the Public Server**
   - Build and run the server:
     ```bash
     go build -o public_server public_server.go
     ./public_server -publicAddr :8080 -publicTLSAddr :8443 -metricsAddr :9090 -config config.yaml
     ```

   - **Use aaPanel**: Add the application as a managed process if desired.

---

### **Local Machine Setup (Kali Linux)**

#### 1. **Install Dependencies**
   - Ensure Go is installed:
     ```bash
     sudo apt install golang -y
     go version  # Confirm installation
     ```

#### 2. **Set Up Project Files**
   - Clone your repository or copy the files:
     ```bash
     git clone https://github.com/your-repo/tunneling-system.git
     cd tunneling-system
     ```

#### 3. **Run the Local Server**
   - Modify the `local_server.go` connection address to match the Azure VM's public IP:
     ```bash
     publicServerAddr = flag.String("publicServerAddr", "ws://<Azure_Public_IP>:8080/ws", "Public server WebSocket address")
     ```
   - Build and run the local server:
     ```bash
     go build -o local_server local_server.go
     ./local_server -publicServerAddr ws://<Azure_Public_IP>:8080/ws -localServiceAddr localhost:3000
     ```

---

### **Verify the Setup**
1. **Local Server Status:**
   - Open a browser and visit `http://localhost:3000` on your Kali Linux machine to ensure your local server is running.

2. **Public Server Access:**
   - Access the Azure server:
     - Metrics: `http://<Azure_Public_IP>:9090/metrics`
     - Proxy Endpoint: `http://<Azure_Public_IP>:8080`
   - Test the tunnel:
     - Access the proxied local server via `http://<Azure_Public_IP>:8080`.

---

### **Optional Improvements**
1. **Add TLS on Public Server**:
   - Use `https://<Azure_Public_IP>:8443` for secure connections.

2. **Automate Startup**:
   - Use `systemd` to create service files for the public server and local server:
     ```bash
     sudo nano /etc/systemd/system/public_server.service
     ```
     Example file:
     ```ini
     [Unit]
     Description=Public Server
     After=network.target

     [Service]
     ExecStart=/path/to/public_server -publicAddr :8080 -publicTLSAddr :8443 -metricsAddr :9090 -config config.yaml
     Restart=always

     [Install]
     WantedBy=multi-user.target
     ```

     Enable and start:
     ```bash
     sudo systemctl enable public_server
     sudo systemctl start public_server
     ```

---

### **Security Tips**
1. **Restrict CIDR in `config.yaml`** to your development IP or network.
2. **Secure Firewall Rules**:
   - Only open necessary ports on Azure and aaPanel.
3. **Authentication**:
   - Add authentication (API keys or tokens) to WebSocket and HTTP endpoints.

