use serde::{Deserialize, Serialize};
use net_guardia_common::model::http_method::EbpfHttpMethod;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    TRACE,
    CONNECT,
}

impl HttpMethod {
    pub fn convert_to_ebpf(http_methods: Vec<HttpMethod>) -> EbpfHttpMethod {
        let mut ebpf_http_method = 0_u16;
        for http_method in http_methods {
            match http_method {
                HttpMethod::GET => ebpf_http_method |= 0b0000_0000_0000_0001,
                HttpMethod::POST => ebpf_http_method |= 0b0000_0000_0000_0010,
                HttpMethod::PUT => ebpf_http_method |= 0b0000_0000_0000_0100,
                HttpMethod::DELETE => ebpf_http_method |= 0b0000_0000_0000_1000,
                HttpMethod::HEAD => ebpf_http_method |= 0b0000_0000_0001_0000,
                HttpMethod::OPTIONS => ebpf_http_method |= 0b0000_0000_0010_0000,
                HttpMethod::PATCH => ebpf_http_method |= 0b0000_0000_0100_0000,
                HttpMethod::TRACE => ebpf_http_method |= 0b0000_0000_1000_0000,
                HttpMethod::CONNECT => ebpf_http_method |= 0b0000_0001_0000_0000,
            }
        }
        ebpf_http_method
    }
}
