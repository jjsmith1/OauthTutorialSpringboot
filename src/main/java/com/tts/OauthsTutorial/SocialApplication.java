package com.tts.OauthsTutorial;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

    @GetMapping("/user")
    public Map<String, Object> user(@AuthenticationPrincipal OauthsTutoriaUser principal) {
        return Collections.singletonMap("name", principal.getAttribute("name"));
    }

    public static void main(String[] args) {
        SpringApplication.run(SocialApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests(a -> a
                        .antMatchers("/", "/error", "/webjars/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .oauth2Login();
        // @formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                // ... existing code here
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )
        // ... existing code here
        // @formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                // ... existing code here
                .csrf(c -> c
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))

        // ... existing code here
        // @formatter:on
    }

    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                // ... existing configuration
                .oauth2Login(o -> o
                        .failureHandler((request, response, exception) -> {
                            request.getSession().setAttribute("error.message", exception.getMessage());
                            handler.onAuthenticationFailure(request, response, exception);
                        })
                );

        @GetMapping("/error")
        public String error(HttpServletRequest request) {
            String message = (String) request.getSession().getAttribute("error.message");
            request.getSession().removeAttribute("error.message");
            return message;
        }
        @Bean
        public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(WebClient rest) {
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            return request -> {
                OAuth2User user = delegate.loadUser(request);
                if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
                    return user;
                }

                OAuth2AuthorizedClient client = new OAuth2AuthorizedClient
                        (request.getClientRegistration(), user.getName(), request.getAccessToken());
                String url = user.getAttribute("organizations_url");
                List<Map<String, Object>> orgs = rest
                        .get().uri(url)
                        .attributes(oauth2AuthorizedClient(client))
                        .retrieve()
                        .bodyToMono(List.class)
                        .block();

                if (orgs.stream().anyMatch(org -> "spring-projects".equals(org.get("login")))) {
                    return user;
                }

                throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Not in Spring Team", ""));
            };
        }
    }}

