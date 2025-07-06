package com.example.jwt1.test;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        final String jwtSchemeName = "JWT";

        return new OpenAPI()
                .info(new Info()
                        .title("JWT 인증 API")
                        .description("JWT 기반 로그인/회원가입 API 명세서")
                        .version("v1.0"))
                .addSecurityItem(new SecurityRequirement().addList(jwtSchemeName)) // 👈 글로벌 보안 적용
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes(jwtSchemeName, new SecurityScheme()
                                .name(jwtSchemeName)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                        )
                );
    }
}