package com.example.oidc.resourceserver.config;

import com.example.oidc.resourceserver.security.AccessTokenValidator;
import com.example.oidc.resourceserver.security.BearerTokenAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the {@link BearerTokenAuthenticationFilter} for the protected API path only.
 *
 * <p>By creating the filter through a {@link FilterRegistrationBean} (instead of annotating it as a
 * component), we control exactly which URLs it guards: {@code /api/*}. The home/info endpoints
 * remain public.
 */
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<BearerTokenAuthenticationFilter> bearerTokenFilter(
            AccessTokenValidator validator) {
        FilterRegistrationBean<BearerTokenAuthenticationFilter> registration =
                new FilterRegistrationBean<>(new BearerTokenAuthenticationFilter(validator));
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }
}
