package com.security.security1.config.oauth;

import com.security.security1.config.auth.PrincipalDetails;
import com.security.security1.config.auth.provider.FacebookUserInfo;
import com.security.security1.config.auth.provider.GoogleUserInfo;
import com.security.security1.config.auth.provider.NaverUserInfo;
import com.security.security1.config.auth.provider.OAuth2UserInfo;
import com.security.security1.model.User;
import com.security.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

//구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

   private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    @Autowired
    private UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest){
        System.out.println(userRequest.getClientRegistration());//registrationId로 어떤 OAuth로 로그인 했는지 확인가능
        System.out.println(userRequest.getAccessToken());
        //구글로그인 버튼 클릭 -> 구글로그인창 ->로그인을 완료 -> code를 리턴(OAuth-Client라이브러리)->AccessToken요청
        //userRequest 정보->loadUser 함수 호출->구글로부터 회원프로필 받음
        System.out.println(super.loadUser(userRequest).getAttributes());

        OAuth2User oauth2User =super.loadUser(userRequest);

        OAuth2UserInfo oAuth2UserInfo = null;

        if(userRequest.getClientRegistration().getRegistrationId().equals("google")){
            oAuth2UserInfo=new GoogleUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            oAuth2UserInfo=new FacebookUserInfo(oauth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            oAuth2UserInfo=new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
        }else{
            System.out.println("네이버,구글과 페이스북만 지원");
        }

        //회원가입 강제로 진행
        String provider = userRequest.getClientRegistration().getRegistrationId();//google
        String providerId=oAuth2UserInfo.getProviderId();
        String username=provider+"_"+oAuth2UserInfo.getName();
//        String password= bCryptPasswordEncoder.encode("random");
        String password= new BCryptPasswordEncoder().encode("random");
        String email=oAuth2UserInfo.getEmail();
        String role="ROLE_USER";

        User userEntity=userRepository.findByUsername(username);
        if(userEntity == null){
            userEntity=User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity,oauth2User.getAttributes());
    }

}
