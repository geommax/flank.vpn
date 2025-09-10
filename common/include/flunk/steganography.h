#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace flunk {

// Steganographic techniques for hiding VPN data
class Steganographer {
public:
    Steganographer();
    ~Steganographer();

    // Hide data in fake HTTP content
    bool hide_in_html(const std::vector<uint8_t>& data, std::string& html_content);
    bool extract_from_html(const std::string& html_content, std::vector<uint8_t>& data);

    // Hide data in fake JSON responses
    bool hide_in_json(const std::vector<uint8_t>& data, std::string& json_content);
    bool extract_from_json(const std::string& json_content, std::vector<uint8_t>& data);

    // Hide data in fake image data (PNG headers/metadata)
    bool hide_in_png_metadata(const std::vector<uint8_t>& data, std::vector<uint8_t>& png_data);
    bool extract_from_png_metadata(const std::vector<uint8_t>& png_data, std::vector<uint8_t>& data);

    // Hide data in HTTP headers
    bool hide_in_http_headers(const std::vector<uint8_t>& data, 
                             std::vector<std::pair<std::string, std::string>>& headers);
    bool extract_from_http_headers(const std::vector<std::pair<std::string, std::string>>& headers,
                                  std::vector<uint8_t>& data);

    // Hide data using LSB in fake binary content
    bool hide_using_lsb(const std::vector<uint8_t>& data, 
                       const std::vector<uint8_t>& cover_data,
                       std::vector<uint8_t>& stego_data);
    bool extract_using_lsb(const std::vector<uint8_t>& stego_data,
                          std::vector<uint8_t>& data,
                          size_t expected_length);

    // Generate fake content templates
    std::string generate_fake_html_page(const std::string& title = "Welcome");
    std::string generate_fake_json_api_response();
    std::vector<uint8_t> generate_fake_png_header(uint32_t width = 100, uint32_t height = 100);

private:
    // Base64 encoding for steganography
    std::string base64_encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64_decode(const std::string& encoded);

    // Data embedding utilities
    bool embed_in_whitespace(const std::vector<uint8_t>& data, std::string& text);
    bool extract_from_whitespace(const std::string& text, std::vector<uint8_t>& data);

    // HTML/JSON templates
    std::vector<std::string> html_templates;
    std::vector<std::string> json_templates;
    
    void load_templates();
};

} // namespace flunk