#include "vpn_client.h"
#include "flunk/logger.h"
#include "flunk/utils.h"
#include <iostream>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

using namespace flunk;

static std::unique_ptr<VPNClient> g_client;
static std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    LOG_INFO("Received signal " + std::to_string(signal) + ", disconnecting...");
    g_shutdown_requested = true;
    if (g_client) {
        g_client->disconnect();
    }
}

std::string get_password_hidden() {
    std::string password;
    struct termios old_termios, new_termios;
    
    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &old_termios);
    new_termios = old_termios;
    
    // Disable echo
    new_termios.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
    
    std::cout << "Password: ";
    std::getline(std::cin, password);
    std::cout << std::endl;
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
    
    return password;
}

void print_usage(const char* program_name) {
    std::cout << "FlunkVPN Client - Advanced VPN with anti-censorship capabilities\n\n"
              << "Usage: " << program_name << " <command> [options]\n\n"
              << "Commands:\n"
              << "  connect     Connect to VPN server\n"
              << "  disconnect  Disconnect from VPN server\n"
              << "  status      Show connection status\n"
              << "  stats       Show connection statistics\n"
              << "  help        Show this help message\n"
              << "  version     Show version information\n\n"
              << "Connect Options:\n"
              << "  -s, --server <host>     Server hostname or IP address\n"
              << "  -p, --port <port>       Server port (default: 1194)\n"
              << "  -u, --username <user>   Username for authentication\n"
              << "  -c, --config <file>     Configuration file path\n"
              << "  -a, --auto-reconnect    Enable automatic reconnection\n"
              << "  -e, --evasion           Enable evasion techniques\n"
              << "  -v, --verbose           Enable verbose logging\n"
              << "  -d, --daemon            Run in background\n\n"
              << "Examples:\n"
              << "  " << program_name << " connect -s vpn.example.com -u myuser\n"
              << "  " << program_name << " connect -s 192.168.1.100 -p 443 -u myuser -e\n"
              << "  " << program_name << " status\n"
              << "  " << program_name << " disconnect\n"
              << std::endl;
}

void print_version() {
    std::cout << "FlunkVPN Client v1.0.0\n"
              << "Advanced VPN with anti-censorship capabilities\n"
              << "Built with OpenSSL and libsodium\n"
              << std::endl;
}

void print_status(VPNClient& client) {
    auto stats = client.get_statistics();
    
    std::cout << "FlunkVPN Connection Status:\n";
    std::cout << "  Status: " << (stats.connected ? "Connected" : "Disconnected") << "\n";
    
    if (stats.connected) {
        std::cout << "  Server: " << stats.server_address << "\n";
        std::cout << "  Assigned IP: " << stats.assigned_ip << "\n";
        std::cout << "  Tunnel: " << (stats.tunnel_active ? "Active" : "Inactive") << "\n";
        std::cout << "  Connected since: " << ctime(&stats.connection_time);
        std::cout << "  Bytes sent: " << stats.bytes_sent << "\n";
        std::cout << "  Bytes received: " << stats.bytes_received << "\n";
        std::cout << "  Last activity: " << ctime(&stats.last_activity);
    }
    std::cout << std::endl;
}

void print_stats(VPNClient& client) {
    auto stats = client.get_statistics();
    
    if (!stats.connected) {
        std::cout << "Not connected to VPN server\n";
        return;
    }
    
    std::cout << "FlunkVPN Statistics:\n";
    std::cout << "  Server Address: " << stats.server_address << "\n";
    std::cout << "  Assigned IP: " << stats.assigned_ip << "\n";
    std::cout << "  Connection Duration: " 
              << Utils::format_duration(std::chrono::seconds(time(nullptr) - stats.connection_time)) << "\n";
    std::cout << "  Data Transferred:\n";
    std::cout << "    Sent: " << stats.bytes_sent << " bytes\n";
    std::cout << "    Received: " << stats.bytes_received << " bytes\n";
    std::cout << "    Total: " << (stats.bytes_sent + stats.bytes_received) << " bytes\n";
    std::cout << "  Tunnel Status: " << (stats.tunnel_active ? "Active" : "Inactive") << "\n";
    std::cout << "  Current Evasion: " << client.get_current_evasion_technique() << "\n";
    std::cout << std::endl;
}

int cmd_connect(int argc, char* argv[]) {
    std::string server_host;
    uint16_t server_port = 1194;
    std::string username;
    std::string config_file = "/etc/flunk_vpn/client.conf";
    bool auto_reconnect = false;
    bool enable_evasion = false;
    bool verbose = false;
    bool daemon_mode = false;

    // Parse connect command options
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-s" || arg == "--server") {
            if (i + 1 < argc) {
                server_host = argv[++i];
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                server_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (arg == "-u" || arg == "--username") {
            if (i + 1 < argc) {
                username = argv[++i];
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            }
        } else if (arg == "-a" || arg == "--auto-reconnect") {
            auto_reconnect = true;
        } else if (arg == "-e" || arg == "--evasion") {
            enable_evasion = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        }
    }

    if (server_host.empty()) {
        std::cerr << "Error: Server hostname is required\n";
        return 1;
    }

    if (username.empty()) {
        std::cout << "Username: ";
        std::getline(std::cin, username);
        if (username.empty()) {
            std::cerr << "Error: Username is required\n";
            return 1;
        }
    }

    std::string password = get_password_hidden();
    if (password.empty()) {
        std::cerr << "Error: Password is required\n";
        return 1;
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize logger
    Logger& logger = Logger::instance();
    logger.set_level(verbose ? LogLevel::DEBUG : LogLevel::INFO);
    logger.enable_timestamp(true);
    
    if (!daemon_mode) {
        logger.enable_console_output(true);
    }

    LOG_INFO("Starting FlunkVPN Client connection to " + server_host + ":" + std::to_string(server_port));

    try {
        g_client = std::make_unique<VPNClient>();
        
        if (!g_client->initialize(config_file)) {
            std::cerr << "Error: Failed to initialize client\n";
            return 1;
        }

        if (enable_evasion) {
            g_client->enable_evasion(true);
            LOG_INFO("Evasion techniques enabled");
        }

        if (auto_reconnect) {
            g_client->enable_auto_reconnect(true);
            LOG_INFO("Auto-reconnect enabled");
        }

        std::cout << "Connecting to " << server_host << ":" << server_port << "...\n";
        
        if (!g_client->connect_to_server(server_host, server_port, username, password)) {
            std::cerr << "Error: Failed to connect to server\n";
            return 1;
        }

        std::cout << "Connected successfully!\n";
        
        if (!g_client->establish_tunnel()) {
            std::cerr << "Error: Failed to establish VPN tunnel\n";
            g_client->disconnect();
            return 1;
        }

        std::cout << "VPN tunnel established\n";
        print_status(*g_client);

        // Main loop for connected client
        while (!g_shutdown_requested && g_client->is_connected()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            // Check connection health
            if (!g_client->is_tunnel_active()) {
                LOG_WARN("Tunnel is not active, attempting to re-establish");
                if (!g_client->establish_tunnel()) {
                    LOG_ERROR("Failed to re-establish tunnel");
                    break;
                }
            }
        }

        std::cout << "Disconnecting...\n";
        g_client->disconnect();
        g_client.reset();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Disconnected\n";
    return 0;
}

int cmd_disconnect() {
    // This would typically connect to a running daemon to request disconnection
    // For simplicity, we'll just show a message
    std::cout << "Disconnect command - would signal running client to disconnect\n";
    return 0;
}

int cmd_status() {
    // This would typically connect to a running daemon to get status
    // For simplicity, we'll show a placeholder
    std::cout << "Status command - would query running client status\n";
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "connect") {
        return cmd_connect(argc, argv);
    } else if (command == "disconnect") {
        return cmd_disconnect();
    } else if (command == "status") {
        return cmd_status();
    } else if (command == "help") {
        print_usage(argv[0]);
        return 0;
    } else if (command == "version") {
        print_version();
        return 0;
    } else {
        std::cerr << "Error: Unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }
}