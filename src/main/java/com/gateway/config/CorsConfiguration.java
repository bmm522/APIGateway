package com.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Configuration
public class CorsConfiguration {
	
	@Bean
	public WebFilter corsFilter() {
		return (ServerWebExchange exchange, WebFilterChain chain) -> {
			ServerHttpRequest request = exchange.getRequest();
			if(CorsUtils.isPreFlightRequest(request)) {
				ServerHttpResponse response = exchange.getResponse();
				setResponseHeader(request, response);
				if(request.getMethod() == HttpMethod.OPTIONS) {
					response.setStatusCode(HttpStatus.OK);
					return Mono.empty();
				}
				
			}
			return chain.filter(exchange);
		};
	}

	private void setResponseHeader(ServerHttpRequest request, ServerHttpResponse response) {
		HttpHeaders requestHeaders = request.getHeaders();
		HttpHeaders responseHeaders = response.getHeaders();
		
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, requestHeaders.getOrigin());
		responseHeaders.addAll(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,  requestHeaders.getAccessControlAllowHeaders());
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,  "GET, PUT, POST, DELETE, OPTIONS");
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "ALL");
		responseHeaders.add(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "18000L" );
		
	} 
}