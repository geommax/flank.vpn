#include "flunk/logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdarg>
#include <vector>
#include <filesystem>

namespace flunk {

class Logger::Impl {
public:
    Impl() : level_(LogLevel::INFO), console_output_(true), timestamp_enabled_(true), 
             max_file_size_(100 * 1024 * 1024) {} // 100MB default
    
    ~Impl() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }
    
    LogLevel level_;
    std::string output_file_;
    std::ofstream log_file_;
    bool console_output_;
    bool timestamp_enabled_;
    size_t max_file_size_;
    std::mutex mutex_;
    
    std::string get_timestamp() {
        if (!timestamp_enabled_) return "";
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
    
    std::string level_to_string(LogLevel level) {
        switch (level) {
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::FATAL: return "FATAL";
            default: return "UNKNOWN";
        }
    }
    
    void rotate_log_if_needed() {
        if (!log_file_.is_open() || output_file_.empty()) return;
        
        try {
            auto file_size = std::filesystem::file_size(output_file_);
            if (file_size >= max_file_size_) {
                log_file_.close();
                
                // Create backup filename with timestamp
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                std::stringstream backup_name;
                backup_name << output_file_ << "."
                           << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
                
                std::filesystem::rename(output_file_, backup_name.str());
                
                // Reopen log file
                log_file_.open(output_file_, std::ios::app);
            }
        } catch (const std::exception&) {
            // Ignore filesystem errors
        }
    }
};

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : pimpl(std::make_unique<Impl>()) {}

Logger::~Logger() = default;

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    pimpl->level_ = level;
}

void Logger::set_output_file(const std::string& filename) {
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    
    if (pimpl->log_file_.is_open()) {
        pimpl->log_file_.close();
    }
    
    pimpl->output_file_ = filename;
    
    // Create directory if it doesn't exist
    try {
        auto parent_path = std::filesystem::path(filename).parent_path();
        if (!parent_path.empty()) {
            std::filesystem::create_directories(parent_path);
        }
    } catch (const std::exception&) {
        // Ignore filesystem errors
    }
    
    pimpl->log_file_.open(filename, std::ios::app);
}

void Logger::set_max_file_size(size_t max_size) {
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    pimpl->max_file_size_ = max_size;
}

void Logger::enable_console_output(bool enable) {
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    pimpl->console_output_ = enable;
}

void Logger::enable_timestamp(bool enable) {
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    pimpl->timestamp_enabled_ = enable;
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < pimpl->level_) return;
    
    std::lock_guard<std::mutex> lock(pimpl->mutex_);
    
    std::stringstream log_line;
    
    // Add timestamp
    std::string timestamp = pimpl->get_timestamp();
    if (!timestamp.empty()) {
        log_line << "[" << timestamp << "] ";
    }
    
    // Add level
    log_line << "[" << pimpl->level_to_string(level) << "] ";
    
    // Add message
    log_line << message;
    
    std::string final_message = log_line.str();
    
    // Output to console
    if (pimpl->console_output_) {
        if (level >= LogLevel::ERROR) {
            std::cerr << final_message << std::endl;
        } else {
            std::cout << final_message << std::endl;
        }
    }
    
    // Output to file
    if (pimpl->log_file_.is_open()) {
        pimpl->rotate_log_if_needed();
        pimpl->log_file_ << final_message << std::endl;
        pimpl->log_file_.flush();
    }
}

void Logger::log(LogLevel level, const char* format, ...) {
    if (level < pimpl->level_) return;
    
    va_list args;
    va_start(args, format);
    
    // Calculate required buffer size
    va_list args_copy;
    va_copy(args_copy, args);
    int size = vsnprintf(nullptr, 0, format, args_copy);
    va_end(args_copy);
    
    if (size < 0) {
        va_end(args);
        return;
    }
    
    // Format message
    std::vector<char> buffer(size + 1);
    vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);
    
    log(level, std::string(buffer.data()));
}

} // namespace flunk