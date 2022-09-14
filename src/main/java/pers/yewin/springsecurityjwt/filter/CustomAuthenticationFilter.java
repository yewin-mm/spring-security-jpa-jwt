package pers.yewin.springsecurityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.filter
 */

@Slf4j // for logging
@RequiredArgsConstructor // inject final authenticationManager by creating constructor based dependency injection instead of using @Autowire
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        /**
         * This method will check login is valid or not as per user input username and password when the user call login api.
         * That login api is built-in spring security api,
         * we did override that method and do authenticate for user input username and password and our database username and password
         */
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("username: {}, password: {}", username, password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // to do authenticate with user input username and password with our database username and password,
        // Firstly, it will go to UserServiceImpl class loadUserByUsername method and find as per username (email) and if user existed, it will do authentica
        return  authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        /**
         * This method will come after above login validation was successful.
         * This method is to generate access token and refresh token when the username and password was correct, means authentication was success.
         * For every request, frontend need to send access token (user role based token) to call api and application will do permission for which user can access which api.
         * So, we can't directly call to api, and we must need to add access token when we call to any api.
         * So, that can prevent from hacking like directly call Eg. we can't  localhost:8080/user/getAllUser or localhost:8080/user/delete
         * However, attacker can get access token through javascript on browser based application.
         * So, don't store your tokens in HTML local storage and store that in server side cookies that are not accessible to JavaScript.
         *
         * Access Token is to access(call) api (need to add that token as header in all api calling, without that you can't call api and that is what we call api security.).
         * Even you have access token, you can't call all api because spring security will validate as per your role and permission eg. which api you are able to call.
         * We can control that in SecurityConfig class.
         * Refresh Token is to re-generate access token when it was expired. You can't call api with refresh-token except token/refresh api because that api take refresh token only to re-generae access token.
         *
         */

        User user = (User) authResult.getPrincipal(); // get spring built-in user object, we already put our user and role data to that spring built-in user object in loadUserByUsername method of UserServiceImpl class

        /**
         * you can declare below password key (secret) with final static field under utility constant class,
         * so that can be use in other place like token/refresh api, CustomAuthorizationFilter class, etc.
         * So that you can easily change it in one place if you want (that will impact to others as all place use that field value)
         * and you don't need to worry about secret mismatched case.
         * if not, you need to re-write for same value in others place like token/refresh api and CustomAuthorizationFilter class, and so, it can get typing wrong and it will lead duplicate same code.
         */

        // below password key (secret) is the most important in JWT.
        // To get token actual value (decoding token), they need to know this below secret password key. So, if you put that key inside in your class like below, they don't know that key from outside (frontend, etc).
        // Without knowing below key, they can't decode JWT. So, that's mean they can't hack your system. That is call spring security (login authentication, authorization) and JWT (to verify next api call from attacker). That can cover, secure your application from attacking.
        /** this below code is duplicate with tokenRefresh method of User Controller class.
         *  So, we can create one static method in CommonUtil class and both can call that method to reduce duplicate code.
         **/
        Algorithm algorithms = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
        String accessToken = JWT.create()
                // token subject will be username when you decode token after you have token.
                .withSubject(user.getUsername()) // user.getUsername() will get email as I added in loadUserByUsername method of UserServiceImpl class

                // add current time to 3 minutes to set expire. formula ->> min = 3 multiply by 60 seconds and 1000 milliseconds
                // so, user can use access token for only 3 minutes and after that frontend need to re-generate access token by refresh token by calling api like token/refresh that we need to develop in controller.
                // For testing access token, you can change the expired minutes to 1 or 2 minutes.
                .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())

                // you can retrieve roles from token claim by key 'roles'
                // that roles will only be role name, because we already add role name only to Authorities field of spring built-in user object in loadUserByUsername method of UserServiceImpl class
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithms);

        // refresh token will use when above access token was expired.
        String refreshToken = JWT.create()
                .withSubject(user.getUsername()) // user.getUsername() will get email as I added in loadUserByUsername method of UserServiceImpl class

                // add current time to 90 minutes to set expire (actually we should set refresh token expiry to week or months or years). formula ->> min = 90 multiply by 60 seconds and 1000 milliseconds
                // so, user can use refresh token (to generate new access token) for only 90 minutes
                // after that frontend should let logout to user when refresh token was expired and when user do login again, the new refresh token was generated as this method. (This method will do after login was successful)
                // actually, we should use refresh token rotation rule to prevent hacker attack (hacker can get refresh token, and he can generate access token as his want, and he can come to our application anytime by using that access token. https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
                // For testing refresh token, you can change the expired minutes to 3 or 4 or etc...
                .withExpiresAt(new Date(System.currentTimeMillis() + 90 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithms);



        // we can return tokens back in header field like below
//        response.setHeader("access_token", accessToken);
//        response.setHeader("refresh_token", refreshToken);


//        response.setContentType(MediaType.APPLICATION_JSON.toString());
        response.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part after calling api.

        /*
        // we can return tokens back in body with json format
        Map<String, String> tokens = new HashMap<String, String>();
        tokens.put("access_token", accessToken); // when you get token from postman or your frontend, you can check token in JWT.io website
        tokens.put("refresh_token", refreshToken);

        // return access token and refresh token after login was successful by using output stream.
        // Actually, response object already return, but we need to define what data we will return (eg. token) and what type (eg. json) we will return back.
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        */

        // we can return tokens back in body with json format by using java object
        TokenResponse tokenObject = new TokenResponse();
        tokenObject.setAccessToken(accessToken);
        tokenObject.setRefreshToken(refreshToken);

        /**
         * we can create custom response class for response (eg. class include these fields - status, message, access token, refresh token, etc).
         * So that frontend developer will know that whether token is expired or format wrong or etc.
         * So, if he knew the token is expired, he can call token/refresh api or etc. to do other logic.
         * Here is demo project, so, I don't go with custom class and this is for testing purpose.
         */

        // return access token and refresh token after login was successful by using output stream.
        // Actually, response object already return, but we need to define what data we will return (eg. token) and what type (eg. json) we will return back.
        new ObjectMapper().writeValue(response.getOutputStream(), tokenObject);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        /**
         * This method will process when the authentication was unsuccessful,
         * This method will process after loadUserByUsername method of UserServiceImpl class.
         * eg. wrong username or wrong password.
         */

        response.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part after calling api.
        log.warn("warning: {}", failed.getMessage());

        /**
         * we can create custom response class for response (eg. class include these fields - status, message, access token, refresh token, etc).
         * So that frontend developer will know that whether token is expired or format wrong or etc.
         * So, if he knew the token is expired, he can call token/refresh api or etc. to do other logic.
         * Here is demo project, so, I don't go with custom class and this is for testing purpose.
         */

        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", failed.getMessage());
        new ObjectMapper().writeValue(response.getOutputStream(), errorMap);
    }
}

// we can create new separate class for TokenResponse rather than inside in this class.
// Because it's duplicate with other TokenResponse class which is inside UserController class.
// If we separate class, we don't need to create inner class in both this class and UserController class too, so that we can decrease large amount of code.
@Data
class TokenResponse{
    private String accessToken;
    private String refreshToken;
}
