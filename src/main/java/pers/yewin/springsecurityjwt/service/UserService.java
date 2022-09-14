package pers.yewin.springsecurityjwt.service;

import org.springframework.http.ResponseEntity;
import pers.yewin.springsecurityjwt.model.entity.Role;
import pers.yewin.springsecurityjwt.model.entity.Users;

import java.util.List;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.service
 */

public interface UserService {

    List<Users> getAllUsers();  // should be use return type with page to reduce loading huge amount of users retrieving.

    Users getByEmail(String name);

    ResponseEntity saveUser(Users user);

    ResponseEntity saveRole(Role role);

    ResponseEntity addRoleToUser(String userName, String roleName);

}
