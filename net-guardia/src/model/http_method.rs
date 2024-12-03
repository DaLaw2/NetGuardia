use serde::{Deserialize, Serialize};
use net_guardia_common::model::http_method::EbpfHttpMethod;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
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

impl HttpMethod {
    pub fn convert_from_ebpf(ebpf_http_methods: EbpfHttpMethod) -> Vec<HttpMethod> {
        let value = ebpf_http_methods as u16;
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

    pub fn convert_to_ebpf(http_methods: Vec<HttpMethod>) -> EbpfHttpMethod {
        let mut ebpf_http_method = 0_u16;
        for http_method in http_methods {
            ebpf_http_method |= http_method as u16;
        }
        ebpf_http_method
    }
}
