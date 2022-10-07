package com.security.security1.config;

import com.security.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
//구글 로그인이 완료된 뒤의 후처리가 필요함 1.코드받기(인증)2.엑세스토큰(권한)
// 3.사용자프로필 정보를 가져와서 4.그 정보를 토대로 회원가입을 자동으로 진행시키도 함
//4-2(이메일,전화번호,이름,아이디) 쇼핑몰 -> 집주소
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true) // secured 어노테이션 활성화,preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 ioc로 등록
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()
                .authorizeHttpRequests()
                    .antMatchers("/user/**").authenticated()//인증만 되면 들어갈 수 있는 주소
                    .antMatchers("/manager/**").hasAnyRole("ADMIN","MANAGER")
                    .antMatchers("/admin/**").hasAnyRole("ADMIN")
                    .anyRequest().permitAll()
                    .and()
                .formLogin()
                    .loginPage("/loginForm")
                    .loginProcessingUrl("/login")//login 주소가 호출되면 시큐리티가 대신 로그인 진행
                    .defaultSuccessUrl("/")
                    .and()
                .oauth2Login()
                .loginPage("/loginForm")//구글 로그인이 완료된 후 코드x(엑세스토큰+사용자프로필정보 가져옴)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
    }

    //    public SecurityFilterChain filterChain () throws Exception {
//        http
//                .csrf()
//                .disable()
//                .authorizeHttpRequests()
//                .antMatchers("/user/**").authenticated()//이주소는 인증이 필요함
//                .antMatchers("/manager/**").hasAnyRole("ADMIN","MANAGER")
//                .antMatchers("/admin/**").hasAnyRole("ADMIN")
//                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//                .loginPage("/login");
//        return http.build();
//    }
}
