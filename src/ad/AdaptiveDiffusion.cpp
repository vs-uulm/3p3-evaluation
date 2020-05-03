#include <cmath>
#include "AdaptiveDiffusion.h"

double AdaptiveDiffusion::p(uint32_t eta, uint32_t s, uint32_t h) {
    if(eta == 2)
        return (s-2*h+2)/(s+2);
    else
        return (std::pow(eta-1, s/2.0-h+1)-1) / (std::pow(eta-1, s/2.0+1)-1);
}