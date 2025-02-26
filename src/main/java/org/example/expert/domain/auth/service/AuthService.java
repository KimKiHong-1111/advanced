package org.example.expert.domain.auth.service;

import lombok.RequiredArgsConstructor;
import org.example.expert.config.JwtUtil;
import org.example.expert.config.PasswordEncoder;
import org.example.expert.domain.auth.dto.request.RefreshTokenRequest;
import org.example.expert.domain.auth.dto.request.SigninRequest;
import org.example.expert.domain.auth.dto.request.SignupRequest;
import org.example.expert.domain.auth.dto.response.RefreshTokenResponse;
import org.example.expert.domain.auth.dto.response.SigninResponse;
import org.example.expert.domain.auth.dto.response.SignupResponse;
import org.example.expert.domain.auth.entity.RefreshToken;
import org.example.expert.domain.auth.exception.AuthException;
import org.example.expert.domain.auth.repository.TokenRepository;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.enums.UserRole;
import org.example.expert.domain.user.repository.UserRepository;
import org.example.expert.domain.user.service.UserService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenRepository tokenRepository;

    @Transactional
    public SignupResponse signup(SignupRequest signupRequest) {

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new InvalidRequestException("이미 존재하는 이메일입니다.");
        }

        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        UserRole userRole = UserRole.of(signupRequest.getUserRole());

        User newUser = new User(
                signupRequest.getEmail(),
                encodedPassword,
                userRole
        );
        User savedUser = userRepository.save(newUser);

        String accessToken = jwtUtil.createAccessToken(savedUser.getId(), savedUser.getEmail(), userRole);
        String refreshToken = jwtUtil.createRefreshToken(savedUser.getId(), savedUser.getEmail(), userRole);

        //refreshToken 저장필요
        RefreshToken savedrefreshtoken = new RefreshToken(savedUser.getId(),refreshToken.getBytes());
        tokenRepository.save(savedrefreshtoken);

        return new SignupResponse(accessToken);
    }

    @Transactional
    public SigninResponse signin(SigninRequest signinRequest) {
        User user = userRepository.findByEmail(signinRequest.getEmail()).orElseThrow(
                () -> new InvalidRequestException("가입되지 않은 유저입니다."));

        // 로그인 시 이메일과 비밀번호가 일치하지 않을 경우 401을 반환합니다.
        if (!passwordEncoder.matches(signinRequest.getPassword(), user.getPassword())) {
            throw new AuthException("잘못된 비밀번호입니다.");
        }

        String accessToken = jwtUtil.createAccessToken(user.getId(), user.getEmail(), user.getUserRole());
        String refreshToken = jwtUtil.createRefreshToken(user.getId(), user.getEmail(), user.getUserRole());

        RefreshToken savedrefreshtoken = new RefreshToken(user.getId(),refreshToken.getBytes());
        tokenRepository.save(savedrefreshtoken);

        return new SigninResponse(accessToken);
    }


    @Transactional
    public RefreshTokenResponse refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        String accessToken = refreshTokenRequest.getAccessToken();
        Long userId = jwtUtil.getUserIdFromToken(accessToken);

        //찾기 실패한 경우 예외처리
        RefreshToken refreshToken = tokenRepository
                .findById(userId)
                .orElseThrow(
                        () -> new InvalidRequestException("토큰을 찾을 수 없습니다."));
        //예외의 경우의 수
        //첫번째, 세션이 만료된 경우?-> 다시 로그인하세요.-> 또 토큰 두개 줌.
        User user = userRepository.findById(userId)
                .orElseThrow(()->new InvalidRequestException("유저를 찾을 수 없습니다."));
        //찾았다면 본인인증 성공이니까,
        return new RefreshTokenResponse(jwtUtil.createAccessToken
                (refreshToken.getId(),user.getEmail(),user.getUserRole()));
        // 만약 같다면? 본인이니까, 새로 accesstoken을 지급하겠다.(refresh)
    }
}
