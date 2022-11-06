//package com.gateway.filter;
//
//import static com.gateway.config.CorsConfiguration.setCors;
//
//import java.util.Objects;
//
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//
//import reactor.core.publisher.Mono;
//
//@Component
//public class AutorizationFilter extends AbstractGatewayFilterFactory<AutorizationFilter.Config>{
//	
//	public AutorizationFilter() {
//		super(Config.class);
//	}
//	
//	@Override
//	public GatewayFilter apply(Config config) {
//		return ((exchange, chain) ->{
//			System.out.println(0);
//			ServerHttpRequest request = exchange.getRequest(); // Pre Filter로 적용
//			ServerHttpResponse response = exchange.getResponse(); // Post Filter는 Response로 받아오면 된다.
//			HttpHeaders requestHeaders = request.getHeaders();
//			setCors(request,response);
//			System.out.println(2);
//			if(request.getMethod() == HttpMethod.OPTIONS) {
//				response.setStatusCode(HttpStatus.OK);
//				return Mono.empty();
//			}
//			System.out.println(3);
//			System.out.println(requestHeaders);
//			if(!requestHeaders.containsKey(HttpHeaders.AUTHORIZATION)) { 			//토큰 존재하지 않을때
//				System.out.println("Not have Authorization");
//				return notiUnAuthorized(exchange); 
//			}
//			String authorication  = Objects.requireNonNull(request.getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0); // 빠른 오류 확인 위해서 requiredNonNull 사용.
//			String token = authorication.replace("Bearer", "").trim();
//
//			System.out.println(token);
//			System.out.println(4);
//			if(!token.equals("A.B.C")) { 			//토큰 일치하지 않을때
//				return notiUnAuthorized(exchange);
//			}
//			
//			System.out.println(5);
//			return chain.filter(exchange);
//		});
//	}
//	
//
//	private Mono<Void> notiUnAuthorized(ServerWebExchange exchange) {
//		ServerHttpResponse response = exchange.getResponse();
//		
//		response.setStatusCode(HttpStatus.UNAUTHORIZED);
//		return response.setComplete();
//	}
//	
//	public static class Config{
//		
//	}
//	
//	
//
//	
//}
