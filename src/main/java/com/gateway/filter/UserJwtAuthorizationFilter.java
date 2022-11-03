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
public class UserJwtAuthorizationFilter extends AbstractGatewayFilterFactory<UserJwtAuthorizationFilter.UserJwtAuthorizationConfig>{
	
	public UserJwtAuthorizationFilter() {
		super(UserJwtAuthorizationConfig.class);
	}
	
	@Override
	public GatewayFilter apply(UserJwtAuthorizationConfig config) {
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
					.username(getUserInfoFromJwt(refreshToken, jwtToken, "username"))
					.nickname(getUserInfoFromJwt(refreshToken, jwtToken, "nickname"))
					.email(getUserInfoFromJwt(refreshToken, jwtToken, "email"))
					.birth(getUserInfoFromJwt(refreshToken, jwtToken, "birth"))
					.phone(getUserInfoFromJwt(refreshToken, jwtToken, "phone"))
					.address(getUserInfoFromJwt(refreshToken, jwtToken, "address"))
					.roles(getUserInfoFromJwt(refreshToken, jwtToken, "roles"))
					.provider(getUserInfoFromJwt(refreshToken, jwtToken, "provider"))
					.providerId(getUserInfoFromJwt(refreshToken, jwtToken, "providerId"))
					.createDate(getUserInfoFromJwt(refreshToken, jwtToken, "createDate"))
					.build();
		

					
	}

	private String getUserInfoFromJwt(String refreshToken, String jwtToken, String userInfo) {
		return JWT.require(Algorithm.HMAC512(JwtProperties.SECRET + refreshToken)).build().verify(jwtToken).getClaim(userInfo).asString();
	}

	public static class UserJwtAuthorizationConfig {
		
	}

	
	
}
