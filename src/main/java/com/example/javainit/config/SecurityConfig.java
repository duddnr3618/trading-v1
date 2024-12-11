package com.example.javainit.config;

import com.example.javainit.user.userDetails.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // 개발 중 CSRF 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() // 기본 정적 리소스 경로 허용
                        .requestMatchers("/",
                                "/user/css/**", "/user/js/**", "/user/img/**",
                                "/main/css/**", "/main/js/**", "/main/img/**",
                                "/trading/css/**", "/trading/js/**", "/trading/img/**").permitAll() // 커스텀 정적 리소스 허용
                        .requestMatchers("/user/**").permitAll()  // 로그인 페이지와 사용자 관련 경로 허용
                        .anyRequest().authenticated() // 그 외 경로는 인증 필요
                )
                .formLogin(form -> form
                        // 로그인 페이지
                        .loginPage("/user/loginPage")
                        // 로그인 처리
                        .loginProcessingUrl("/user/login")
                        // 로그인 처리시 인증 필드
                        .usernameParameter("userEmail") // 사용자 정의 필드명 사용
                        // 로그인 성공시 URL
                        .defaultSuccessUrl("/", true)
                        // 로그인 실패시
                        .failureHandler((request, response, exception) -> {
                            String errorMessage = "자격 증명에 실패하였습니다.";
                            String encodedMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8.toString());
                            response.sendRedirect("/user/loginPage?error=true&message=" + encodedMessage);
                        })
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout"))
                        .logoutSuccessUrl("/user/loginPage") // 로그아웃 후 로그인 페이지로 이동
                        .invalidateHttpSession(true)    // 세션 무효화
                        .deleteCookies("JSESSIONID")    // 쿠키 삭제
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 비밀번호 암호화
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
