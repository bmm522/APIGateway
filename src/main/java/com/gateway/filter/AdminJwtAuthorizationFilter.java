package com.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.gateway.entity.User;
import com.gateway.properties.HttpStatusProperties;
import com.gateway.properties.JwtProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AdminJwtAuthorizationFilter extends AbstractGatewayFilterFactory<AdminJwtAuthorizationFilter. AdminJwtAuthorizationConfig>{
	
	public AdminJwtAuthorizationFilter() {
		super(AdminJwtAuthorizationConfig.class);
	}
	
	@Override
	public GatewayFilter apply( AdminJwtAuthorizationConfig config) {
		return ((exchange, chain) -> {
			
			ServerHttpRequest request = exchange.getRequest();
			ServerHttpResponse response = exchange.getResponse();
			
			String jwtHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String serverHeader = request.getHeaders().get("RefreshToken").get(0);
			
			//JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
			if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.JWT_PREFIX)) {
				return notiStatus(exchange, "Not found authorization header", HttpStatus.UNAUTHORIZED);
			}
			
			//정상적인 로그인서버에서 접근한 사용자인지 확인
			if(serverHeader == null || !serverHeader.startsWith(JwtProperties.REFRESHTOKEN_PREFIX)) {
				return notiStatus(exchange, "Not found refreshToken header", HttpStatus.UNAUTHORIZED);
			}
			
			//JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
			String jwtToken = jwtHeader.replace(JwtProperties.JWT_PREFIX, "");
			String refreshToken = serverHeader.replace(JwtProperties.REFRESHTOKEN_PREFIX, "");
			User user = null;
			try {
				user = getUser(jwtToken, refreshToken);
			} catch(Exception e) {
				return notiStatus(exchange, "Token Error", HttpStatus.UNAUTHORIZED);
			}
			
			//관리자인지 체크
			if(!user.getRoles().equals("ROLE_ADMIN")) {
				return notiStatus(exchange, "Don`t exist ROLE_ADMIN ",HttpStatus.UNAUTHORIZED);
			}
			// 서명이 정상적으로 됨
			
			return chain.filter(exchange);
		});	
	}
	
	private Mono<Void> notiStatus(ServerWebExchange exchange,String e, HttpStatus status){
		exchange.getResponse().getHeaders().set(HttpStatusProperties.STATUS, e);
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(status);
		log.error(e);
		return response.setComplete();
	}
	
	private User getUser(String jwtToken, String refreshToken) {
		return User.UserBuilder()
					.username(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("username").asString())
					.nickname(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("nickname").asString())
					.email(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("email").asString())
					.birth(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("birth").asString())
					.phone(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("phone").asString())
					.address(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("address").asString())
					.roles(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("roles").asString())
					.provider(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("provider").asString())
					.providerId(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("providerId").asString())
					.createDate(JWT.require(Algorithm.HMAC512(JwtProperties.SECRET+refreshToken)).build().verify(jwtToken).getClaim("createDate").asString())
					.build();
							
	}
	
	
	public static class  AdminJwtAuthorizationConfig{
		
	}

	
}
