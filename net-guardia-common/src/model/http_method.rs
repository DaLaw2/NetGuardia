#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "user"))]
use std::vec::Vec;

pub type HttpMethodBitmap = u16;

#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, Debug, Eq, PartialEq))]
pub enum HttpMethod {
    GET = 0b0000_0000_0000_0001,
    POST = 0b0000_0000_0000_0010,
    PUT = 0b0000_0000_0000_0100,
    DELETE = 0b0000_0000_0000_1000,
    HEAD = 0b0000_0000_0001_0000,
    OPTIONS = 0b0000_0000_0010_0000,
    PATCH = 0b0000_0000_0100_0000,
    TRACE = 0b0000_0000_1000_0000,
    CONNECT = 0b0000_0001_0000_0000,
}

#[cfg(feature = "user")]
impl HttpMethod {
    pub fn convert_from_bitmap(http_method_bitmap: HttpMethodBitmap) -> Vec<HttpMethod> {
        let value = http_method_bitmap as u16;
        let mut http_methods = Vec::new();

        let all_methods = [
            HttpMethod::GET,
            HttpMethod::POST,
            HttpMethod::PUT,
            HttpMethod::DELETE,
            HttpMethod::HEAD,
            HttpMethod::OPTIONS,
            HttpMethod::PATCH,
            HttpMethod::TRACE,
            HttpMethod::CONNECT,
        ];

        for method in all_methods {
            if value & (method as u16) != 0 {
                http_methods.push(method);
            }
        }
        http_methods
    }

    pub fn convert_to_bitmap(http_methods: Vec<HttpMethod>) -> HttpMethodBitmap {
        let mut ebpf_http_method = 0_u16;
        for http_method in http_methods {
            ebpf_http_method |= http_method as u16;
        }
        ebpf_http_method
    }
}
