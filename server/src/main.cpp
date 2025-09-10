#include "vpn_server.h"
#include "flunk/logger.h"
#include "flunk/utils.h"
#include <iostream>
#include <thread>
#include <signal.h>

using namespace flunk;

static std::unique_ptr<VPNServer> g_server;
static std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int signal) {
    LOG_INFO("Received signal " + std::to_string(signal) + ", shutting down...");
    g_shutdown_requested = true;
    if (g_server) {
        g_server->stop();
    }
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  -c, --config <file>    Configuration file path (default: /etc/flunk_vpn/server.conf)\n"
              << "  -d, --daemon           Run as daemon\n"
              << "  -v, --verbose          Enable verbose logging\n"
              << "  -h, --help             Show this help message\n"
              << "  --version              Show version information\n"
              << std::endl;
}

void print_version() {
    std::cout << "FlunkVPN Server v1.0.0\n"
              << "Advanced VPN with anti-censorship capabilities\n"
              << "Built with OpenSSL and libsodium\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string config_file = "/etc/flunk_vpn/server.conf";
    bool daemon_mode = false;
    bool verbose = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: --config requires a file path\n";
                return 1;
            }
        } else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--version") {
            print_version();
            return 0;
        } else {
            std::cerr << "Error: Unknown option " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe signals

    // Initialize logger
    Logger& logger = Logger::instance();
    if (verbose) {
        logger.set_level(LogLevel::DEBUG);
    } else {
        logger.set_level(LogLevel::INFO);
    }
    
    logger.set_output_file("/var/log/flunk_vpn/server.log");
    logger.enable_timestamp(true);
    
    if (!daemon_mode) {
        logger.enable_console_output(true);
    }

    LOG_INFO("Starting FlunkVPN Server v1.0.0");

    // Check if running as root (required for TUN interface creation)
    if (!Utils::is_root()) {
        LOG_ERROR("FlunkVPN server must be run as root for TUN interface creation");
        std::cerr << "Error: This program must be run as root\n";
        return 1;
    }

    // Create and initialize server
    try {
        g_server = std::make_unique<VPNServer>();
        
        if (!g_server->initialize(config_file)) {
            LOG_ERROR("Failed to initialize server with config file: " + config_file);
            std::cerr << "Error: Failed to initialize server\n";
            return 1;
        }

        LOG_INFO("Server initialized successfully");

        // Start server
        if (!g_server->start()) {
            LOG_ERROR("Failed to start server");
            std::cerr << "Error: Failed to start server\n";
            return 1;
        }

        LOG_INFO("Server started successfully");

        // Main loop
        while (!g_shutdown_requested && g_server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Print periodic statistics
            static time_t last_stats_time = 0;
            time_t current_time = time(nullptr);
            if (current_time - last_stats_time >= 60) {  // Every minute
                auto stats = g_server->get_statistics();
                LOG_INFO("Server Stats - Active clients: " + std::to_string(stats.current_active_clients) +
                        ", Total served: " + std::to_string(stats.total_clients_served) +
                        ", Bytes transferred: " + std::to_string(stats.total_bytes_transferred));
                last_stats_time = current_time;
            }
        }

        LOG_INFO("Shutting down server...");
        g_server->stop();
        g_server.reset();

    } catch (const std::exception& e) {
        LOG_ERROR("Server exception: " + std::string(e.what()));
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    LOG_INFO("FlunkVPN Server shutdown complete");
    return 0;
}