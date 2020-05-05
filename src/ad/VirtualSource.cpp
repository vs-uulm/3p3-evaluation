#include <cmath>
#include "VirtualSource.h"

VirtualSource::VirtualSource(std::vector<uint32_t>& neighbors, std::vector<uint8_t> message)
: neighbors_(neighbors), message_(message) {

}

VirtualSource::VirtualSource(std::vector<uint32_t>& neighbors, std::vector<uint8_t> message, std::vector<uint8_t> token)
: neighbors_(neighbors), message_(message) {
    // TODO decode the VS Token
}

void VirtualSource::forwardMessage() {

}