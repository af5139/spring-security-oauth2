package com.security.security1.config.auth;
//시큐리티가 login 을 주소 요청이 오면 낚아채서 로그인을 진행시킴
//로그인을 진행이 완료가 되면 session을 만들어줌.(Security ContextHolder)에 세션정보를 저장시킴
//오브젝트 = Authentication 타입 객체
//authentication 안에 user 정보가 있어야 됨.
//user 오브젝트타입=>UserDetails 타입 객체

//시큐리티가 세션 => authentication 객체 => UserDetails

import com.security.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String,Object> attributes;

    //일반로그인
    public PrincipalDetails(User user){
        this.user=user;
    }
    //OAuth 로그인
    public PrincipalDetails(User user,Map<String,Object> attributes){
        this.user=user;
        this.attributes=attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    //해당 user 의 권한을 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        // 우리사이트 1년동안 회원이 로그인을 안할경우 휴먼계정이됨
        //현재시간 - 로그인시간 => 1년을 초과하면 return false
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
