#pragma once

#include <string>
#include <memory>
#include <thread>
#include <mutex>

namespace flunk {

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

class Logger {
public:
    static Logger& instance();
    
    void set_level(LogLevel level);
    void set_output_file(const std::string& filename);
    void set_max_file_size(size_t max_size);
    void enable_console_output(bool enable);
    void enable_timestamp(bool enable);
    
    void log(LogLevel level, const std::string& message);
    void log(LogLevel level, const char* format, ...);
    
    void trace(const std::string& message) { log(LogLevel::TRACE, message); }
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warn(const std::string& message) { log(LogLevel::WARN, message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }
    void fatal(const std::string& message) { log(LogLevel::FATAL, message); }

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

// Convenience macros
#define LOG_TRACE(msg) flunk::Logger::instance().trace(msg)
#define LOG_DEBUG(msg) flunk::Logger::instance().debug(msg)
#define LOG_INFO(msg) flunk::Logger::instance().info(msg)
#define LOG_WARN(msg) flunk::Logger::instance().warn(msg)
#define LOG_ERROR(msg) flunk::Logger::instance().error(msg)
#define LOG_FATAL(msg) flunk::Logger::instance().fatal(msg)

} // namespace flunk