package pers.yewin.springsecurityjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pers.yewin.springsecurityjwt.model.entity.Role;
import pers.yewin.springsecurityjwt.model.entity.Users;
import pers.yewin.springsecurityjwt.service.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.controller
 */

@RestController
@RequiredArgsConstructor // inject final userService by creating constructor based dependency injection instead of using @Autowire
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @GetMapping("/getAllUser")
    public ResponseEntity<List<Users>> getAllUsers(){
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @GetMapping("/getUserByEmail")
    public ResponseEntity<Users> getUserByEmail(@RequestParam("email") String email){
        return ResponseEntity.ok().body(userService.getByEmail(email));
    }

    @PostMapping("/createUser")
    public ResponseEntity createUser(@RequestBody Users users){
        return userService.saveUser(users);
    }

    @PostMapping("/role/createRole")
    public ResponseEntity createRole(@RequestBody Role role){
        return userService.saveRole(role);
    }

    @PostMapping("/role/addRoleToUser")
    public ResponseEntity addRoleToUser(@RequestBody AddRoleToUserRequest addRoleToUserRequest){
        return userService.addRoleToUser(addRoleToUserRequest.getEmail(), addRoleToUserRequest.getRoleName());
    }

    /**
     * You can add more methods like delete user,
     * If so, please don't delete physically and just play with deleted true, false.
     * Here, I do demo project and so, I don't add that kind of methods.
     */


    @GetMapping("/token/refresh")
    public void tokenRefresh(HttpServletRequest request, HttpServletResponse response) throws IOException { // we want token value from header, so, we request as HttpServletRequest

        /**
         * This method is to re-generate access token by input refresh token.
         * So, refresh token is to re-generate access token if access token was expired.
         * So, as per security concerns we should set access token expired time to short time (eg. 1 or 3 or 5 min)
         * If not so, when the hacker got our access token, they can get our system by access token anytime, so we should set expired to that access token.
         * Refresh token approach is to change access token key (re-generate access token) in every short time (if access token was expired).
         * So we don't need to afraid if hacker got our access token because it will expire in a short time and it will generate as new key in every short time by refresh token.
         * For that case, front end developer need to call our token refresh api if he got access token was expired error message and frontend need to give refresh token in header when calling this api which refresh token can get after calling login api.
         * We should generate new refresh token and return with other way to frontend because hacker can get refresh token too. Because if he got that refresh token, he can enter our system by access token and even access token was expired, he can generate new token by using refresh token if he knew refresh token. https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
         * But here, I just return new access token only as this is security basic demo application.
         */

        try{
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            String bearer = "Bearer "; // include space behind Bearer as key will follow after space

            if (authorizationHeader != null && authorizationHeader.startsWith(bearer)) {
                String refreshToken = authorizationHeader.substring(bearer.length()); // cut header for starting bearer keyword and take all key text behind bearer by substring method.


                /**
                 * you can declare below password key (secret) with final static field under utility constant class,
                 * so that can be use in other place like CustomAuthorizationFilter, CustomAuthenticationFilter class, etc.
                 * So that you can easily change it in one place if you want (that will impact to others as all place use that field value)
                 * and you don't need to change in all place if you add in one place.
                 * and also you don't need to worry about secret mismatched case.
                 * if not, you need to re-write for same value in others place like CustomAuthorizationFilter and CustomAuthenticationFilter class, and so, it can get typing wrong, and it will lead duplicate same code.
                 */

                // create algorithm object by password key that password key must need to be same with Token generating secret key. which is generated in CustomAuthenticationFilter class.
                // you can declare password key (secret) under utility constant class (if not, you can create that class for constant fields and value) and that can be use in both CustomAuthenticationFilter and this class. So that you don't need to worry about secret mismatched case.
                Algorithm algorithm = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // create JWT verify with algorithm to verify user input token.
                DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken); // decode token

                // retrieve roles from claim by using key 'roles' as we gave that in CustomAuthenticationFilter class.
                String [] roles = decodedJWT.getClaim("roles").asArray(String.class); // we gave that as String array (Authorities), so we need to convert to String array when we pull that roles.

                // check if roles is null or not empty for user
                if(roles != null && roles.length != 0) {

                    // if roll is not null or empty,
                    // that is access token because we didn't add role in refresh token, we added roles in only access token in successfulAuthentication method of CustomAuthenticationFilter.
                    // we don't let user do generate new access tokens by existing access token.
                    throw new RuntimeException("Token is not valid.");
                }

                String email = decodedJWT.getSubject(); // subject will be email as we gave that in CustomAuthenticationFilter class.

                Users user = userService.getByEmail(email);


                /** this below code is duplicate with successfulAuthentication method of CustomAuthenticationFilter class.
                 *  So, we can create one static method in CommonUtil class and both can call that method to reduce duplicate code.
                 **/
                Algorithm algorithms = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                String accessToken = JWT.create()
                        // token subject will be username when you decode token after you have token.
                        .withSubject(user.getEmail()) // user.getUsername() will get email as I added in loadUserByUsername method of UserServiceImpl class

                        // add current time to 3 minutes to set expire. formula ->> min = 3 multiply by 60 seconds and 1000 milliseconds
                        // so, user can use access token for only 3 minutes and after that frontend need to re-generate access token by refresh token by calling api like token/refresh that we need to develop in controller.
                        // For testing access token, you can change the expired minutes to 1 or 2 minutes.
                        .withExpiresAt(new Date(System.currentTimeMillis() + 3 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())

                        // Here we don't need to add authorities like successfulAuthentication method of CustomAuthenticationFilter class.
                        // because we don't check for authorities as we already checked in successfulAuthentication method of CustomAuthenticationFilter class.
                        // so, we add our plain role name only in claim
                        .withClaim("roles", user.getRoleList().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithms);

                /**
                 * here we don't need to generate again for refresh token as refresh token expiry time is long time (eg. 1 day, week, month, year , etc)
                 * So, we will re-generate only for access token.
                 * **/


                response.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part after calling login api.

                /*
                Map<String, String> tokens = new HashMap<String, String>();
                tokens.put("access_token", accessToken); // when you get token from postman or your frontend, you can check token in JWT.io website
                tokens.put("refresh_token", refreshToken);

                new ObjectMapper().writeValue(response.getOutputStream(), tokens);*/

                // we can return tokens back in body with json format by using java object
                TokenResponse tokenObject = new TokenResponse();
                tokenObject.setAccessToken(accessToken);
                tokenObject.setRefreshToken(refreshToken);

                /**
                 * we can create custom response class for response (eg. response class may include these fields - status, message, access token, refresh token, etc).
                 * So that frontend developer will know that whether token is expired or format wrong or etc.
                 * So, if he knew the token is expired, he can call token/refresh api.
                 */

                new ObjectMapper().writeValue(response.getOutputStream(), tokenObject);

            }
            else {
                /**
                 * we can create custom response class for response (eg. response class may include these fields - status, message, access token, refresh token, etc).
                 * So that frontend developer will know that whether token is expired or format wrong or etc.
                 * So, if he knew the token is expired, he can call token/refresh api.
                 */
                throw new RuntimeException("Token format is wrong");
            }

        }catch (Exception e) {
            response.setHeader("error ", e.getMessage());
            response.setStatus(FORBIDDEN.value());
            Map<String, String> errorJson = new HashMap<>();
            errorJson.put("error: ", e.getMessage());
            errorJson.put("code: ", String.valueOf(FORBIDDEN.value()));
            errorJson.put("message: ", "Your input refresh token is something wrong");
            response.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part.

            /**
             * we can create custom response class for response (eg. response class may include these fields - status, message, access token, refresh token, etc).
             * So that frontend developer will know that whether token is expired or format wrong or etc.
             * So, if he knew the token is expired, he can call token/refresh api or etc. to do other logic.
             * Here is demo project, so, I don't go with custom class and this is for testing purpose.
             */

            // return json type data by writing output stream to httpServletResponse
            new ObjectMapper().writeValue(response.getOutputStream(), errorJson);
        }
    }

}

@Data
class AddRoleToUserRequest {
    private String email;
    private String roleName;
}

// we can create new separate class for TokenResponse rather than inside in this class.
// Because it's duplicate with other TokenResponse class which is inside CustomAuthenticationFilter class.
// If we separate class, we don't need to create inner class in both this class and CustomAuthenticationFilter too, so that we can decrease large amount of code.
@Data
class TokenResponse{
    private String accessToken;
    private String refreshToken;
}