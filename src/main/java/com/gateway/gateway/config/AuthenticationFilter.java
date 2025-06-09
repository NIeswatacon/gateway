package com.gateway.gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    // A mesma chave secreta do conta-service. Coloque-a no application.properties do Gateway.
    @Value("${jwt.secret}")
    private String jwtSecret;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Verifica se a rota é pública (ex: login) e a deixa passar sem verificação.
            if (isPublicRoute(exchange)) {
                return chain.filter(exchange);
            }

            // Verifica se o cabeçalho Authorization existe.
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            
            // Verifica se o formato é "Bearer <token>".
            if (!authHeader.startsWith("Bearer ")) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            try {
                // Valida o token e extrai o ID do usuário.
                Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
                String userId = claims.getSubject();

                // Injeta o ID do usuário em um novo cabeçalho para os serviços internos usarem.
                exchange.getRequest().mutate().header("X-User-ID", userId).build();

            } catch (Exception e) {
                // Se o token for inválido (expirado, assinatura incorreta, etc.).
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            // Se tudo estiver OK, a requisição continua para o serviço de destino.
            return chain.filter(exchange);
        };
    }
    
    // Método auxiliar para rotas públicas
    private boolean isPublicRoute(ServerWebExchange exchange) {
        return exchange.getRequest().getURI().getPath().contains("/api/contas/auth");
    }

    // Método auxiliar para retornar um erro
    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    public static class Config {}
}